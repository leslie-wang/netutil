package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"text/tabwriter"

	"golang.org/x/net/route"
)

const note = `
mac os route definition: https://opensource.apple.com/source/network_cmds/network_cmds-356.8/netstat.tproj/netstat.1.auto.html
1  RTF_PROTO1    Protocol specific routing flag #1
2  RTF_PROTO2    Protocol specific routing flag #2
3  RTF_PROTO3    Protocol specific routing flag #3
B  RTF_BLACKHOLE Just discard packets (during updates)
b  RTF_BROADCAST The route represents a broadcast address
C  RTF_CLONING   Generate new routes on use
c  RTF_PRCLONING Protocol-specified generate new routes on use
D  RTF_DYNAMIC   Created dynamically (by redirect)
G  RTF_GATEWAY   Destination requires forwarding by intermediary
H  RTF_HOST      Host entry (net otherwise)
I  RTF_IFSCOPE   Route is associated with an interface scope
i  RTF_IFREF     Route is holding a reference to the interface
L  RTF_LLINFO    Valid protocol to link address translation
M  RTF_MODIFIED  Modified dynamically (by redirect)
m  RTF_MULTICAST The route represents a multicast address
R  RTF_REJECT    Host or net unreachable
S  RTF_STATIC    Manually added
U  RTF_UP        Route usable
W  RTF_WASCLONED Route was generated as a result of cloning
X  RTF_XRESOLVE  External daemon translates proto to link address

freebsd definition: https://www.freebsd.org/cgi/man.cgi?query=netstat&sektion=1
https://www.freebsd.org/doc/handbook/network-routing.html
1 RTF_PROTO1     Protocol specific routing flag #1
2 RTF_PROTO2     Protocol specific routing flag #2
3 RTF_PROTO3     Protocol specific routing flag #3
B RTF_BLACKHOLE  Just  discard  pkts (during updates)
b RTF_BROADCAST  The route represents  a broadcast address
D RTF_DYNAMIC    Created dynamically (by redirect)
G RTF_GATEWAY    Destination requires  forwarding by intermediary
H RTF_HOST       Host  entry (net otherwise)
L RTF_LLINFO     Valid protocol to link address translation
M RTF_MODIFIED   Modified dynamically  (by redirect)
R RTF_REJECT     Host  or net unreachable
S RTF_STATIC     Manually added
U RTF_UP         Route usable
X RTF_XRESOLVE   External daemon translates proto to link address

https://apple.stackexchange.com/questions/336888/whats-the-meanings-of-the-routing-tables-data-in-the-mac-os
`

func main() {
	fmt.Println("mac's equivalant command: net -nr")

	pkt, err := route.FetchRIB(syscall.AF_INET, syscall.NET_RT_DUMP, 0)
	if err != nil {
		log.Fatal(err)
	}
	msgs, err := route.ParseRIB(route.RIBTypeRoute, pkt)
	if err != nil {
		log.Fatal(err)
	}
	writer := tabwriter.NewWriter(os.Stdout, 10, 2, 2, ' ', 0)
	defer writer.Flush()

	writer.Write([]byte("Destination\tGateway\tNetif\tFlags\n"))

	for i, msg := range msgs {
		if m, ok := msg.(*route.RouteMessage); ok {
			dump(i, m, writer)
		} else {
			fmt.Println("received non route message: ", msg)
		}
	}
}

func dump(i int, msg *route.RouteMessage, writer io.Writer) {
	if isFlagGateway(msg.Flags) && isFlagHost(msg.Flags) && isFlagIFRef(msg.Flags) {
		return
	}

	intf, err := net.InterfaceByIndex(msg.Index)
	if err != nil {
		fmt.Printf("unable to find interface %d, %v\n", msg.Index, err)
		return
	}

	len := 0
	for i, a := range msg.Addrs {
		if a == nil {
			len = i
			break
		}
	}

	if len < 2 {
		fmt.Printf("address should have at least 2 entries, but got %v\n", msg)
		return
	}
	destIP, ok := msg.Addrs[0].(*route.Inet4Addr)
	if !ok {
		fmt.Printf("destination address should be route.Inet4Addr, but got %v\n", msg.Addrs[0])
		return
	}

	destination := fmt.Sprintf("%d.%d.%d.%d", destIP.IP[0], destIP.IP[1], destIP.IP[2], destIP.IP[3])
	if len == 3 {
		if msg.Addrs[2].Family() != syscall.AF_INET {
			fmt.Printf("3rd address should be AF_INET type mask, but got %v\n", msg.Addrs[2])
			return
		}
		a, ok := msg.Addrs[2].(*route.Inet4Addr)
		if !ok {
			fmt.Printf("3rd address should be route.Inet4Addr, but got %v\n", msg.Addrs[2])
			return
		}
		l, _ := net.IPv4Mask(a.IP[0], a.IP[1], a.IP[2], a.IP[3]).Size()
		if l == 0 {
			destination = "default"
		} else {
			destination = fmt.Sprintf("%s/%d", destination, l)
		}
	}

	gateway := ""
	if msg.Addrs[1].Family() == syscall.AF_INET {
		gw, ok := msg.Addrs[1].(*route.Inet4Addr)
		if !ok {
			fmt.Printf("Unknown gateway INET addrs %v\n", msg.Addrs[1])
			return
		}
		gateway = fmt.Sprintf("%d.%d.%d.%d", gw.IP[0], gw.IP[1], gw.IP[2], gw.IP[3])
	} else if msg.Addrs[1].Family() == syscall.AF_LINK {
		link, ok := msg.Addrs[1].(*route.LinkAddr)
		if !ok {
			fmt.Printf("Unknown gateway link addrs %v\n", msg.Addrs[1])
			return
		}
		if len == 3 {
			gateway = fmt.Sprintf("link#%d", link.Index)
		} else {
			a := []string{}
			for _, b := range link.Addr {
				a = append(a, fmt.Sprintf("%x", b))
			}
			gateway = strings.Join(a, ":")
		}
	} else {
		fmt.Printf("Unknown gateway addrs %v\n", msg.Addrs[1])
		return
	}

	writer.Write(
		[]byte(
			fmt.Sprintf("%v\t%v\t%v\t%v\n",
				destination,
				gateway,
				intf.Name,
				getFlags(msg.Flags),
			)))
}

func dumpAll(i int, msg *route.RouteMessage) {
	fmt.Printf("---route msg %d: Type: %d%v, Flag: %d%v, Index: %d\n", i, msg.Type, getTypes(msg.Type), msg.Flags, getFlags(msg.Flags), msg.Index)
	for j, a := range msg.Addrs {
		if a == nil {
			continue
		}
		if a.Family() == syscall.AF_INET {
			na, ok := a.(*route.Inet4Addr)
			if ok {
				fmt.Printf("inet addrs %d: %v\n", j, na.IP)
			} else {
				fmt.Printf("Unknown INET addrs %d: %d, %v\n", j, a.Family(), a)
			}
		} else if a.Family() == syscall.AF_LINK {
			na, ok := a.(*route.LinkAddr)
			if ok {
				fmt.Printf("link addrs %d: name: %s, index: %d, addr: %v\n", j, na.Name, na.Index, na.Addr)
			} else {
				fmt.Printf("Unknown link addrs %d: %d, %v\n", j, a.Family(), a)
			}
		} else {
			fmt.Printf("Unknown addrs %d: %d, %v\n", j, a.Family(), a)
		}
	}
}

func isFlagGateway(t int) bool {
	return t&syscall.RTF_GATEWAY == syscall.RTF_GATEWAY
}

func isFlagHost(t int) bool {
	return t&syscall.RTF_HOST == syscall.RTF_HOST
}

func isFlagIFRef(t int) bool {
	return t&syscall.RTF_IFREF == syscall.RTF_IFREF
}

func getTypes(t int) []string {
	ret := []string{}
	if t&syscall.RTM_ADD == syscall.RTM_ADD {
		ret = append(ret, "RTM_ADD")
	}
	if t&syscall.RTM_CHANGE == syscall.RTM_CHANGE {
		ret = append(ret, "RTM_CHANGE")
	}
	if t&syscall.RTM_DELADDR == syscall.RTM_DELADDR {
		ret = append(ret, "RTM_ADD")
	}
	if t&syscall.RTM_DELETE == syscall.RTM_DELETE {
		ret = append(ret, "RTM_DELETE")
	}
	if t&syscall.RTM_DELMADDR == syscall.RTM_DELMADDR {
		ret = append(ret, "RTM_DELMADDR")
	}
	if t&syscall.RTM_GET == syscall.RTM_GET {
		ret = append(ret, "RTM_GET")
	}
	if t&syscall.RTM_GET2 == syscall.RTM_GET2 {
		ret = append(ret, "RTM_GET2")
	}
	if t&syscall.RTM_IFINFO == syscall.RTM_IFINFO {
		ret = append(ret, "RTM_IFINFO")
	}
	if t&syscall.RTM_IFINFO2 == syscall.RTM_IFINFO2 {
		ret = append(ret, "RTM_IFINFO2")
	}
	if t&syscall.RTM_LOCK == syscall.RTM_LOCK {
		ret = append(ret, "RTM_LOCK")
	}
	if t&syscall.RTM_LOSING == syscall.RTM_LOSING {
		ret = append(ret, "RTM_LOSING")
	}
	if t&syscall.RTM_MISS == syscall.RTM_MISS {
		ret = append(ret, "RTM_MISS")
	}
	if t&syscall.RTM_NEWADDR == syscall.RTM_NEWADDR {
		ret = append(ret, "RTM_NEWADDR")
	}
	if t&syscall.RTM_NEWMADDR == syscall.RTM_NEWMADDR {
		ret = append(ret, "RTM_NEWMADDR")
	}
	if t&syscall.RTM_NEWMADDR2 == syscall.RTM_NEWMADDR2 {
		ret = append(ret, "RTM_NEWMADDR2")
	}
	if t&syscall.RTM_OLDADD == syscall.RTM_OLDADD {
		ret = append(ret, "RTM_OLDADD")
	}
	if t&syscall.RTM_OLDDEL == syscall.RTM_OLDDEL {
		ret = append(ret, "RTM_OLDDEL")
	}
	if t&syscall.RTM_REDIRECT == syscall.RTM_REDIRECT {
		ret = append(ret, "RTM_REDIRECT")
	}
	if t&syscall.RTM_RESOLVE == syscall.RTM_RESOLVE {
		ret = append(ret, "RTM_RESOLVE")
	}
	if t&syscall.RTM_RTTUNIT == syscall.RTM_RTTUNIT {
		ret = append(ret, "RTM_RTTUNIT")
	}
	if t&syscall.RTM_VERSION == syscall.RTM_VERSION {
		ret = append(ret, "RTM_VERSION")
	}
	return ret
}

func getFlags(t int) []string {
	ret := []string{}
	if t&syscall.RTF_BLACKHOLE == syscall.RTF_BLACKHOLE {
		ret = append(ret, "RTF_BLACKHOLE")
	}
	if t&syscall.RTF_BROADCAST == syscall.RTF_BROADCAST {
		ret = append(ret, "RTF_BROADCAST")
	}
	if t&syscall.RTF_CLONING == syscall.RTF_CLONING {
		ret = append(ret, "RTF_CLONING")
	}
	if t&syscall.RTF_CONDEMNED == syscall.RTF_CONDEMNED {
		ret = append(ret, "RTF_CONDEMNED")
	}
	if t&syscall.RTF_DELCLONE == syscall.RTF_DELCLONE {
		ret = append(ret, "RTF_DELCLONE")
	}
	if t&syscall.RTF_DONE == syscall.RTF_DONE {
		ret = append(ret, "RTF_DONE")
	}
	if t&syscall.RTF_DYNAMIC == syscall.RTF_DYNAMIC {
		ret = append(ret, "RTF_DYNAMIC")
	}
	if t&syscall.RTF_GATEWAY == syscall.RTF_GATEWAY {
		ret = append(ret, "RTF_GATEWAY")
	}
	if t&syscall.RTF_HOST == syscall.RTF_HOST {
		ret = append(ret, "RTF_HOST")
	}
	if t&syscall.RTF_IFREF == syscall.RTF_IFREF {
		ret = append(ret, "RTF_IFREF")
	}
	if t&syscall.RTF_IFSCOPE == syscall.RTF_IFSCOPE {
		ret = append(ret, "RTF_IFSCOPE")
	}
	if t&syscall.RTF_LLINFO == syscall.RTF_LLINFO {
		ret = append(ret, "RTF_LLINFO")
	}
	if t&syscall.RTF_LOCAL == syscall.RTF_LOCAL {
		ret = append(ret, "RTF_LOCAL")
	}
	if t&syscall.RTF_MODIFIED == syscall.RTF_MODIFIED {
		ret = append(ret, "RTF_MODIFIED")
	}
	if t&syscall.RTF_MULTICAST == syscall.RTF_MULTICAST {
		ret = append(ret, "RTF_MULTICAST")
	}
	if t&syscall.RTF_PINNED == syscall.RTF_PINNED {
		ret = append(ret, "RTF_PINNED")
	}
	if t&syscall.RTF_PRCLONING == syscall.RTF_PRCLONING {
		ret = append(ret, "RTF_PRCLONING")
	}
	if t&syscall.RTF_PROTO1 == syscall.RTF_PROTO1 {
		ret = append(ret, "RTF_PROTO1")
	}
	if t&syscall.RTF_PROTO2 == syscall.RTF_PROTO2 {
		ret = append(ret, "RTF_PROTO2")
	}
	if t&syscall.RTF_PROTO3 == syscall.RTF_PROTO3 {
		ret = append(ret, "RTF_PROTO3")
	}
	if t&syscall.RTF_REJECT == syscall.RTF_REJECT {
		ret = append(ret, "RTF_REJECT")
	}
	if t&syscall.RTF_STATIC == syscall.RTF_STATIC {
		ret = append(ret, "RTF_STATIC")
	}
	if t&syscall.RTF_UP == syscall.RTF_UP {
		ret = append(ret, "RTF_UP")
	}
	if t&syscall.RTF_WASCLONED == syscall.RTF_WASCLONED {
		ret = append(ret, "RTF_WASCLONED")
	}
	if t&syscall.RTF_XRESOLVE == syscall.RTF_XRESOLVE {
		ret = append(ret, "RTF_XRESOLVE")
	}

	return ret
}
