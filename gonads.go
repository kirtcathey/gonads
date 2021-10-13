package main

import (
	"./searchscan"
	"bufio"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
)

//var num = 0  // number of cycles/scans tracker
const banner string = `
---------------------------------------------------------	
01000111 01101111 01001110 01000001 01000100 01010011
---------------------------------------------------------
/e88~~\           888b    |      e      888~-_   ,d88~~\ 
d888      e88~-_  |Y88b   |     d8b     888   \  8888    
8888 __  d888   i | Y88b  |    /Y88b    888    | 'Y88b
8888   | 8888   | |  Y88b |   /  Y88b   888    |  'Y88b, 
Y888   | Y888   ' |   Y88b|  /____Y88b  888   /     8888 
\"88__/  \"88_-~  |    Y888 /      Y88b 888_-~   \__88P' 
---------------------------------------------------------
--. --- -. .- -.. ...
---------------------------------------------------------`

type services struct {
	fqdn      string
	ipaddress string
	// portServiceVersion	[]string <--- Ultimately want to split this up into an array of strings
	portServiceVersion string // <---- Just take a dump for the time-being...
}

type subdomain struct {
	fqdn           string
	ipaddress      []string
	serviceVersion []services
}

type target struct {
	// add to this struct as functionality is added, such as depth, and other info collection modules
	targetDomain string
	authDNS      string
	subDomains   []subdomain
}

/*func (r target) getServices() {
	// We want to get our own TEXT format to layout the presentation and design, but for the time-being,
	// can we just use nmap out to XML? However, do gather the data and write to CSV!!
	lines, err := ReadCsv(r.targetDomain + "-IP-subdomain-cert-search.csv")
	if err != nil {
		panic(err)
	}
	// Loop through lines & turn into object
	i := 0
	subDom := make([]subdomain, len(lines))
	for _, line := range lines {
		x := 0
		for _, str := range strings.Split(line, ",") {
			if x == 0 {
				subDom[i].fqdn = str
			}
			if x > 0 {
				subDom[i].ipaddress = append(subDom[i].ipaddress, str)
			}
			x++
		}
		i++
	}
	var f *os.File
	for _, sub := range subDom {
		i = 0
		sub.serviceVersion = make([]services, len(sub.ipaddress))
		if sub.ipaddress != nil {
			for _, ip := range sub.ipaddress {
				// scan, _ := nmap.Init().AddHosts(ip).IntenseAllTCPPorts().Run()
				sub.serviceVersion[i].ipaddress = ip
				sub.serviceVersion[i].fqdn = sub.fqdn // Redundant, but necessary?
				if _, err := os.Stat(r.targetDomain + "-" + time.Now().Format("20060102") + "-nmap-services.xml"); err == nil {
					f, _ = os.OpenFile(r.targetDomain+"-"+time.Now().Format("20060102")+"-nmap-services.xml", os.O_APPEND|os.O_WRONLY, 0755)
					str := string(searchscan.NmapScan(ip, sub.fqdn))
					// <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><?xml-stylesheet href="file:///C:/Program Files (x86)/Nmap/nmap.xsl" type="text/xsl"?> // Windows
					// <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?> // Linux
					str = strings.Replace(str, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprun><?xml-stylesheet href=\"file:///usr/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?>", "", -1)
					_, err := f.Write([]byte(str))
					if err != nil{
						panic(err)
					}
				} else {
					f, _ = os.Create(r.targetDomain + "-" + time.Now().Format("20060102") + "-nmap-services.xml")
					str := string(searchscan.NmapScan(ip, sub.fqdn))
					// <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE nmaprun><?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?> //Linux, Windows is above...
					str = strings.Replace(str, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprun><?xml-stylesheet href=\"file:///usr/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?>", "", -1)
					_,err := f.Write([]byte(str))
					if err != nil{
						panic(err)
					}
				}
			}
		}
		i++
	}
	i++
	if f != nil {
		defer func(f *os.File) {
			err := f.Close()
			if err != nil {
				panic(err)
			}
		}(f)
	}
	searchscan.CleanXML(r.targetDomain, r.targetDomain+"-"+time.Now().Format("20060102")+"-nmap-services.xml")
	// Remove original nmap produced XML
	err = os.Remove(r.targetDomain+"-"+time.Now().Format("20060102")+"-nmap-services.xml")
	if err != nil {
		panic(err)
	}
}*/

func (r target) assignIPs() {
	// Open CSV file and lookup ipaddress and append to "ipaddress-results.csv"
	lines, err := ReadCsv(r.targetDomain + "-subdomain-cert-search.csv")
	if err != nil {
		panic(err)
	}

	// Loop through lines & turn into object
	i := 0
	data := make([]subdomain, len(lines))
	for _, line := range lines {
		//data = append(data, data[i])
		line = strings.Replace(line,"\"","",-1)
		data[i].fqdn = line
		fmt.Println(data[i].fqdn)
		// Lookup IP address for the fqdn
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Millisecond * time.Duration(10000),
				}
				return d.DialContext(ctx, network, "8.8.8.8:53")
			},
		}
		ip, _ := r.LookupHost(context.Background(), data[i].fqdn)
		data[i].ipaddress = ip
		i++
	}
	// Write to new CSV file
	csvfile, err := os.Create(r.targetDomain + "-IP-subdomain-cert-search.csv")
	if err != nil {
		fmt.Println("Failed creating file: ", err)
	}
	csvwriter := csv.NewWriter(csvfile)

	for _, sub := range data {
		writestring := make([]string, len(sub.ipaddress)+1)
		for i = 0; i <= len(sub.ipaddress); i++ {
			if i == 0 {
				writestring[i] = sub.fqdn
			} else {
				writestring[i] = sub.ipaddress[i-1]
			}
		}
		_ = csvwriter.Write(writestring)
	}
	csvwriter.Flush()
	if csvfile.Close() != nil {
		fmt.Println("Something went wrong when writing CERT subdomains!")
	}
	// delete old CSV file
	err = os.Remove(r.targetDomain + "-subdomain-cert-search.csv")
	if err != nil {
		panic(err)
	}
}

func (r target) run() bool {
	// function to return sub-domains from public certificates.
	if searchscan.CertSearch(r.targetDomain, "crt") == false {
		fmt.Println("Subdomain Certificate Search Complete!")
	}
	// function to return sub-domains from DNS interrogation.
	searchscan.DNSSSearch(r.targetDomain, r.authDNS)
	return true
}

/*func convertXML(target string) {
	fn := target + "-" + time.Now().Format("20060102") + "-nmap-services-formatted.xml -o " + target + "-" + time.Now().Format("20060102") + "-nmap-services-formatted.html"
	cmd := exec.Command("bash", "-c", "xsltproc "+fn, os.Getenv("PATH"))
	err_ := cmd.Run()
	if err_ != nil {
		fmt.Println(err_)
	}
}*/

func ReadCsv(filename string) ([]string, error) {
	// Open TXT file
	bytesRead, _ := ioutil.ReadFile(filename)
	f := string(bytesRead)
	lines := strings.Split(f, "\n")

	return lines, nil
}

func menu(tgt string, cycle int) bool {
	var num int = cycle
	var sub []subdomain

	fmt.Print(banner + "\n")

	var r = target{tgt, "8.8.8.8", sub}
	if num == 0 {
		fmt.Print("Gathering and scanning from the top-level domain (TLD): \n" + tgt + "\nOr, enter ctrl-C to exit the program. \n")
		r.targetDomain = tgt //assign the target domain to the model
		if r.run() {
			r.assignIPs()              // assign IP addresses to subdomains gathered
			saveIPs(r.targetDomain, r.targetDomain + "-ip-targets.txt")
			//r.getServices()            // NMap scan initially for services that may be running
			//convertXML(r.targetDomain) // convert the xml output from nmap
			scan := "-sS -sU -T4 -A -v -Pn " + r.targetDomain + " -oX " + r.targetDomain + "-1ST-scan.xml -iL " + r.targetDomain + "-ip-targets.txt"
			searchscan.DeepScan(r.targetDomain, scan, "1ST")
			uploadHTML(r.targetDomain + "-1ST-scan.xml")
			uploadHTML(r.targetDomain + "-1ST-scan.html")
			println("Initial run complete! Go to the directory you ran GoNADS from, and open your favorite file.")
			num++  // increment to gather unique IPs do next scan in switch statement (case 1)
			menu(r.targetDomain, 1) // back to menu
		}
	}
	if num > 0 {
		fmt.Print("Continuing with additional scans now... \n\n")
		//if strings.Trim(cnt, "\n") == "C" {
			switch {
			case num == 1:
				msg := `
While executing additional scans on IP addresses identified, take some time
to review what has been found so far. Review the html and text files created from
subdomain enumeration, IP gathering, and scan results in the following directory: `
				gwd, err := os.Getwd()
				if err != nil {
					panic(err)
				}
				fmt.Print(banner + "\n")
				fmt.Print(msg + "\n" + gwd + "/\n")
				//Now do the scanning...
				r.targetDomain = tgt
				ip := make([]string, 0)
				//scanData, _ := ioutil.ReadFile(r.targetDomain + "-" + time.Now().Format("20060102") + "-nmap-services.xml")
				scanData, _ := ioutil.ReadFile(r.targetDomain + "-1ST-scan.xml")
				// parse (unmarshal) the XML document read into mem
				xmlRunner, e := searchscan.Parse(scanData)
				if e != nil {
					fmt.Println("Error: searchscan.Parse() returned nil.")
					return true //true is 1, so there was an error...
				}
				// get the IP addresses from the XML doc
				ip = getIPAddresses(xmlRunner)
				// Now remove duplicates and write to comma delimited
				ip, _ = removeDuplicateValues(ip)
				// save to text file (one IP address per line)
				saveStringArray(ip, r.targetDomain + "-ip-targets.txt")
				saveHosts(r.targetDomain, r.targetDomain + "-host-targets.txt")
				scan := "-sV -sF -" + "-scanflags PSH -T4 -oX " + r.targetDomain + "-2ND-scan.xml -iL " + r.targetDomain + "-ip-targets.txt"
				searchscan.DeepScan(r.targetDomain, scan, "2ND")
				uploadHTML(r.targetDomain + "-2ND-scan.xml")
				uploadHTML(r.targetDomain + "-2ND-scan.html")
				num++
				var _ = menu(r.targetDomain, 2)
				// Find higher risk nmap scans and do a mid-scan
			case num == 2:
				msg := `
Now executing a slower, deeper scan on IP addresses identified. Please stand by.
In the mean time, review the html and text files for subdomain enumeration,
IP gathering, and scan results in the following directory: `
				gwd, err := os.Getwd()
				if err != nil {
					panic(err)
				}
				fmt.Print(banner + "\n")
				fmt.Print(msg + "\n" + gwd + "/\n")
				//Now do the scanning...
				// Slower deeper scan
				// nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script \"default or (discovery and safe)\" " + target
				// ######################################################################### "--" will throw an error!!
				scan := "-Pn -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 -" + "-script \"default or (discovery and safe)\" -oX " + r.targetDomain + "-3RD-scan.xml -iL " + r.targetDomain + "-ip-targets.txt"
				searchscan.DeepScan(r.targetDomain, scan, "3RD")
				uploadHTML(r.targetDomain + "-3RD-scan.xml")
				uploadHTML(r.targetDomain + "-3RD-scan.html")
				num++
				var _ = menu(tgt, 3)
				// Do a mid-scan on the other medium or lower risk nmap results
			case num == 3:
				msg := `
Now executing a slower, deeper scan by subdomain FQDN (instead of IP address) identified. Please stand by.
In the mean time, review the html and text files for subdomain enumeration,
IP gathering, and scan results in the following directory: `
				gwd, err := os.Getwd()
				if err != nil {
					panic(err)
				}
				fmt.Print(banner + "\n")
				fmt.Print(msg + "\n" + gwd + "/\n")
				//Now do the scanning...
				scan := "-sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 -" + "-script \"default or (discovery and safe)\" -oX " + r.targetDomain + "-HOSTS-scan.xml -iL " + r.targetDomain + "-host-targets.txt"
				searchscan.DeepScan(r.targetDomain, scan, "HOSTS")
				uploadHTML(r.targetDomain + "-HOSTS-scan.xml")
				uploadHTML(r.targetDomain + "-HOSTS-scan.html")
				num++
				var _ = menu(tgt, 4)
			/*case num == 4:
				msg := `
Now doing an email search on search engines. Please stand by.
In the mean time, review the html and text files for subdomain enumeration,
IP gathering, and scan results in the following directory: `
				gwd, err := os.Getwd()
				if err != nil {
					panic(err)
				}
				fmt.Print(banner + "\n")
				fmt.Print(msg + "\n" + gwd + "/\n")
				//Now do it here ...
				num++
				var _ = menu(tgt, 5)
				// Even more information gathering
			case num == 5:
				fmt.Print(banner + "\n")
				num++
				var _ = menu(tgt, 6)
				// Then even more information gathering*/
			default:
/*				fmt.Print(banner + "\n")
				fmt.Println("Exhaustive scan of " + r.targetDomain + " complete!")
				fmt.Println(banner)
				fmt.Println("Press ctrl-C to exit.")*/
				num = 0
				os.Exit(0)
			}
		//}else{menu(tgt)}
	}
	return false
}

func getIPAddresses(xmlRunner *searchscan.NmapRunner) []string {
	var z = 0 //counter to append the ip string slice
	ip := make([]string,0)
	for x := range xmlRunner.NmapRuns {
		if len(xmlRunner.NmapRuns[x].Hosts) >= 1 {
			for i := range xmlRunner.NmapRuns[x].Hosts {
				if len(xmlRunner.NmapRuns[x].Hosts[i].Addresses) >= 1 {
					for a := range xmlRunner.NmapRuns[x].Hosts[i].Addresses {
						//searchscan.SecondScan(r.targetDomain, xmlRunner.NmapRuns[x].Hosts[i].Addresses[a].Addr)
						// Gather the IPs into a slice, remove duplicates, then save to a list
						ip = append(ip, xmlRunner.NmapRuns[x].Hosts[i].Addresses[a].Addr)
						z++
					}
				}
			}
		}
	}
	return ip
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

// Function to get a list of subdomain hosts to run through nmap
func saveIPs(tgt string, fn string){
	f, err := os.Open(tgt + "-IP-subdomain-cert-search.csv")
	if err != nil {
		panic(err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	ips := make([]string,0)
	//x := 0
	for _, line := range lines {
		// counter
		//x++
		s := strings.Split(line, ",")
		if len(s) > 1 {
			cs := strings.Replace(s[1], "*.", "", -1) //Replace any wildcard listings
			ips = append(ips, cs)
		}
	}
	ipList, _ := removeDuplicateValues(ips)
	saveStringArray(ipList, fn)
}

// Function to get a list of subdomain hosts to run through nmap
func saveHosts(tgt string, fn string){
	f, err := os.Open(tgt + "-IP-subdomain-cert-search.csv")
	if err != nil {
		panic(err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	hosts := make([]string,0)
	//x := 0
	for _, line := range lines {
		// counter
		//x++
		s := strings.Split(line, ",")
		cs := strings.Replace(s[0], "*.", "",-1) //Replace any wildcard listings
		hosts = append(hosts, cs)
		// hosts[x] = strings.Replace(hosts[x], "*.", "",-1) //Replace any wildcard listings
	}
	hosts, _ = removeDuplicateValues(hosts)
	saveStringArray(hosts, fn)
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

func uploadHTML(fn string){
	const (
		// Need to login from command line once to get public key in known_hosts file
		user string = "YOUR_USERNAME"
		pass string = "YOUR_PASSWORD"
		remote string = "YOUR_IP_ADDRESS"
		port string = ":PORT_NUMBER"
	)

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// connect
	conn, err := ssh.Dial("tcp", remote+port, config)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	// create new SFTP client
	client, err := sftp.NewClient(conn)
	if err != nil {
		panic(err)
	}
	defer client.Close()
	// create destination file
	dstFile, err := client.Create("/home/jpleakso/gnads/scans/" + fn)
	if err != nil {
		panic(err)
	}
	defer dstFile.Close()
	// create source file
	srcFile, err := os.Open(fn)
	if err != nil {
		panic(err)
	}
	// copy source file to destination file
	bytes, err := io.Copy(dstFile, srcFile)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d bytes copied\n", bytes)
}

func main() {
	wordPtr := flag.String("t", "", "tld")
	flag.Parse()
	if *wordPtr == "" {
		fmt.Print("USAGE: \n# ./gonads -t=example.com\nPlease input a valid top-level domain to analyze.\n")
		os.Exit(0)
	}else {
		fmt.Print(banner + "\n\n")
		if menu(*wordPtr, 0) != true {
			var _ = menu(*wordPtr, 0)
		} else {
			fmt.Println("GoNADS exited...")
		}
	}
}
