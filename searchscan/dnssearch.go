package searchscan

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

func DNSSSearch(targetdomain string, authdns string) {
	// set program's default DNS
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Millisecond * time.Duration(10000),
			}
			fmt.Println(authdns)
			return d.DialContext(ctx, network, authdns + ":53")
			//return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}
	ipaddr, _ := r.LookupHost(context.Background(), targetdomain)
	//ipaddr, _ := r.LookupIP(context.Background(), "ipv4", targetdomain)
	// print(ip[0])

	//ipaddr, _ := net.LookupIP(targetdomain)
	records, _ := net.LookupNS(targetdomain)

	if ipaddr != nil {
		//fmt.Println("IP Address(es) for " + targetdomain + " ......................")
		//for _, ip := range ipaddr {
		//	fmt.Println(ip)
		//}
		rip, _ := removeDuplicateValues(ipaddr)
		saveStringArray(rip, targetdomain + "-ip-targets.txt")
	}
	if records != nil {
		hosts := make([]string,0)
		fmt.Println("Authoritative NS Server for " + targetdomain +" ......................")
		for _, rec := range records {
			hosts = append(hosts, rec.Host)
			//fmt.Println(rec.Host)
		}
		hosts, _ = removeDuplicateValues(hosts)
		saveStringArray(hosts, targetdomain + "-host-targets.txt")
	}
}

func removeDuplicateValues(stringSlice []string) ([]string, error) {
	keys := make(map[string]bool)
	list := make([]string,0)
	for _, entry := range stringSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list, nil
}

// Saves an array of strings... send a string array and file name to save to
func saveStringArray(sa []string, fn string) {
	//save to a new line delimited text file
	file, err := os.OpenFile(fn, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	dataWriter := bufio.NewWriter(file)
	for _, data := range sa {
		_, _ = dataWriter.WriteString(data + "\n")
	}
	err = dataWriter.Flush()
	if err != nil {
		panic(err)
	}
	err = file.Close()
	if err != nil {
		panic(err)
	}
}