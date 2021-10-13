package searchscan

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/loglist"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	_ "github.com/mattn/go-sqlite3"
	_ "github.com/tcnksm/go-latest"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
)

var (
	//githubTag = &latest.GithubTag{
	//	Owner:             "netevert",
	//	Repository:        "delator",
	//	FixVersionStrFunc: latest.DeleteFrontV()}
	iloop			= 0
	logCount        = 0
	logSize         = uint64(0)
	writer          = new(tabwriter.Writer)
	wg              = &sync.WaitGroup{}
	newSet          = flag.NewFlagSet("newSet", flag.ContinueOnError)
	domain          = newSet.String("d", "", "input domain")
	source          = newSet.String("s", "", "search source")
	resolve         = newSet.Bool("a", false, "view A record")
	store           = newSet.Bool("p", false, "pull ct logs")
//	ver             = newSet.Bool("v", false, "version check")
	outcsv          = newSet.Bool("csv", false, "output to csv")
	utilDescription = "delator -d <domain> -s <source> {db|crt} [-apv] -csv"
//	myClient        = &http.Client{Timeout: 10 * time.Second}
)

type data struct {
	IssuerCaID        int    `json:"issuer_ca_id"`
	IssuerName        string `json:"issuer_name"`
	NameValue         string `json:"name_value"`
	MinCertID         int    `json:"min_cert_id"`
	MinEntryTimestamp string `json:"min_entry_timestamp"`
	NotAfter          string `json:"not_after"`
	NotBefore         string `json:"not_before"`
}

type record struct {
	Subdomain string `json:"subdomain"`
	A         string `json:"a_record"`
}

type logSelection struct {
	selectionNumber int
	logValue        string
	logSize         uint64
	status          string
}

type sortByLength []string

// Len implements Len of sort.Interface
func (s sortByLength) Len() int {
	return len(s)
}

// Swap implements Swap of sort.Interface
func (s sortByLength) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less implements Less of sort.Interface
func (s sortByLength) Less(i, j int) bool {
	return len(s[i]) > len(s[j])
}

// helper function to print errors and exit
func printError(err string) {
	fmt.Println("error:", err)
	os.Exit(1)
}

// helper function to grab url and robustly handle errors
func grabURL(URL string) (resp *http.Response) {
	resp, err := http.Get(URL)
	if err, ok := err.(*url.Error); ok {
		if err.Timeout() {
			printError("request timed out")
		} else if err.Temporary() {
			printError("temporary error")
		} else {
			printError(fmt.Sprintf("%s", err.Err))
		}
	}
	if resp != nil && resp.StatusCode != 200 {
		printError(fmt.Sprintf("unexpected status code returned: %d", resp.StatusCode))
	}
	return resp
}

// fetches certificate transparency json data
func fetchData(URL string) []data {
	if *outcsv != false {
		fmt.Printf("\r%s", "writing to csv")
	}
	res := grabURL(URL)
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		fmt.Println(err)
	}

	keys := make([]data, 0)
	err = json.Unmarshal([]byte(body), &keys)
	if err != nil {
		return nil
	}
	return keys
}

// reads from  a record type channel and prints to csv
func writeToCsv(out chan record){
	file, err := os.Create(*domain + time.Now().Format("20060102") + "-cert.sh-result.csv")
	if err != nil {
		fmt.Println(err)
	}

	defer file.Close()
	csvwriter := csv.NewWriter(file)
	defer csvwriter.Flush()
	for r := range out {
		var tmp = []string{r.Subdomain, r.A}
		err := csvwriter.Write(tmp)
		if err != nil {
			fmt.Println(err)
		}
	}
	fmt.Printf("\r%s                    \n", "done")
}

// deduplicates and prints subdomains, if csv output is selected the
// method writes to csv
func printData(Data []data) {
	//if *outcsv != false {
	// Make it always out CSV for the time being
	counter := make(map[string]int)
	//Need to assign a more definitive name (e.g., target domain name identifier) to csv file.
	file, err := os.Create(*domain + "-subdomain-cert-search.csv")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	for _, i := range Data {
		counter[i.NameValue]++
		if counter[i.NameValue] == 1 {
			var tmp = []string{i.NameValue}
			err := writer.Write(tmp)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
	fmt.Printf("\r%s                    \n", "done")
	//}
	//if *outcsv == false {
	//	counter := make(map[string]int)
	//	for _, i := range Data {
	//		counter[i.NameValue]++
	//		if counter[i.NameValue] == 1 {
	//			fmt.Println(i.NameValue)
	//		}
	//	}
	//}
}

// helper function to return the number of characters
// in the longest string within an array. To be used
// to calculate the minwidth for TabWriters
func getMinWidth(targetList []string) int {
	// We sort it by length, descending
	sort.Sort(sortByLength(targetList))

	// The first element is sure to be the longest
	longest := []string{targetList[0]}
	return len(longest[0])

}

// helper function to run lookups and print results
func printResults(subdomains []string) {
	out := make(chan record)
	writer.Init(os.Stdout, getMinWidth(subdomains), 8, 0, '\t', tabwriter.DiscardEmptyColumns)
	runConcurrentLookups(subdomains, *resolve, out)
	go monitorWorker(wg, out)
	if *outcsv != false {
		writeToCsv(out)
	}
	if *outcsv == false {
		for r := range out {
			fmt.Fprintln(writer, r.Subdomain + "\t" + r.A + "\t")
			writer.Flush()
		}
	}
}

// deduplicates and returns subdomain list
func extractSubdomains(Data []data) []string {
	counter := make(map[string]int)
	var subdomains []string
	for _, i := range Data {
		tmp := strings.Split(i.NameValue, "\n")
		for _, splitWord := range tmp {
			counter[splitWord]++
			if counter[splitWord] == 1 {
				subdomains = append(subdomains, splitWord)
			}
		}
	}
	return subdomains
}

// validates domains using regex
func validateDomainName(domain string) bool {
	patternStr := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`
	patternStr1 := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9]))$`
	RegExp := regexp.MustCompile(patternStr)
	RegExp1 := regexp.MustCompile(patternStr1)
	if RegExp.MatchString(domain) {
		return true
	} else if RegExp1.MatchString(domain) {
		return true
	} else {return false}
}

// performs an A record DNS lookup
func aLookup(subdomain string) string {
	ip, err := net.ResolveIPAddr("ip4", subdomain)
	if err != nil {
		return ""
	}
	return ip.String() // todo: fix to return only one IP
}

// performs lookups on individual subdomain record
func doLookups(subdomain string, resolve bool, out chan<- record) {
	defer wg.Done()
	r := new(record)
	r.Subdomain = subdomain
	if resolve {
		r.A = aLookup(r.Subdomain)
	}
	out <- *r
}

// runs bulk lookups on list of subdomains
func runConcurrentLookups(subdomains []string, resolve bool, out chan<- record) {
	for _, subdomain := range subdomains {
		wg.Add(1)
		go doLookups(subdomain, resolve, out)
	}
}

// helper function to wait for goroutines collection to finish and close channel
func monitorWorker(wg *sync.WaitGroup, channel chan record) {
	wg.Wait()
	close(channel)
}

// sanitizes domain inputs
func sanitizedInput(input string) (sanitizedDomain string) {
	if !validateDomainName(input) {
		fmt.Printf("\nplease supply a valid domain\n\n")
		// fmt.Println(utilDescription)
		// newSet.PrintDefaults()
		os.Exit(1)
	}
	sanitizedDomain, _ = publicsuffix.EffectiveTLDPlusOne(input)
	return "%." + sanitizedDomain
}

// dumps retrieved common name into delator database
func dumpData(CommonName string) {
	database, _ := sql.Open("sqlite3", "./data.db")
	statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS subdomains (id INTEGER PRIMARY KEY, subdomain TEXT)")
	statement.Exec()
	statement, _ = database.Prepare("INSERT INTO subdomains (subdomain) VALUES (?)")
	statement.Exec(CommonName)
	database.Close()
}

// dumps cert information into local database
func logCertInfo(entry *ct.RawLogEntry) {
	logCount++
	fmt.Printf("\rProgress: %d/%d", logCount, logSize)
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		fmt.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		commonName := parsedEntry.X509Cert.Subject.CommonName
		if commonName != "" {
			dumpData(commonName)
		}
	}
}

// dumps precert information into local database
func logPrecertInfo(entry *ct.RawLogEntry) {
	logCount++
	fmt.Printf("\rProgress: %d/%d", logCount, logSize)
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		fmt.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		commonName := parsedEntry.Precert.TBSCertificate.Subject.CommonName
		if commonName != "" {
			dumpData(commonName)
		}
	}
}

// helper function to create regexes
func createRegexes(regexValue string) (*regexp.Regexp, *regexp.Regexp) {
	// Make a regex matcher
	var certRegex *regexp.Regexp
	precertRegex := regexp.MustCompile(regexValue)
	certRegex = precertRegex
	return certRegex, precertRegex
}

// fetches certificate transparency json data
func grabKnownLogs(URL string) *loglist.LogList {
	myClient := &http.Client{Timeout: time.Second * 10}

	llData, err := x509util.ReadFileOrURL(URL, myClient)
	if err != nil {
		// glog.Exitf("Failed to read log list: %v", err) // TODO
	}

	ll, err := loglist.NewFromJSON(llData)
	if err != nil {
		// glog.Exitf("Failed to read log list: %v", err) // TODO
	}
	return ll
}

// prints a list of all known certificate transparency logs
func storeKnownLogs() bool {
	writer.Init(os.Stdout, 10, 8, 0, '\t', tabwriter.AlignRight)
	fmt.Fprintln(writer, "Selection\tLog size\tStatus\tLog URL\t")
	fmt.Fprintln(writer, "---------\t--------\t------\t-------\t")
	var collection []logSelection
	var maxSelection = 0
	logData := grabKnownLogs("https://www.gstatic.com/ct/log_list/log_list.json")
	for i := range logData.Logs {
		maxSelection = i
		var tmp logSelection
		log := logData.Logs[i]
		tmp.selectionNumber = i
		tmp.logValue = log.URL
		tmp.status = "available"
		size, err := grabLogSize("https://" + log.URL)
		if err != nil {
			tmp.status = "unavailable"
		}
		tmp.logSize = size
		s := fmt.Sprintf("%d\t%d\t%s\t%s\t", tmp.selectionNumber, tmp.logSize, tmp.status, tmp.logValue)
		fmt.Fprintln(writer, s)
		writer.Flush()
		collection = append(collection, tmp)
	}
	if readSelection(collection, maxSelection) == false {
		return false
	} else { return true }
}

// helper function to read user supplied answer and start ct log download
func readSelection(data []logSelection, maxSelection int) bool {
	selectionRange := makeRange(0, maxSelection)
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Select log (default 'ct.googleapis.com/pilot/') [all | 0-%d] (or \"XX\" to return/exit): ", maxSelection)
	text, _ := reader.ReadString('\n')
	text = strings.Replace(text, "\r\n", "", -1)
	//text = strings.TrimSuffix(text, "\n")
	if text == "" {
		// download default log
		iloop ++
		grabCTLog("https://ct.googleapis.com/pilot/")
	} else if text == "all" {
		// download data for all logs
		iloop ++
		downloadCTLogs()
	} else if text == "XX" {
		if iloop == 0 {
			// Query the user about skipping, not having database data downloaded, etc..
			fmt.Println(`You haven't initialized a database, or have chosen not to perform
							 a certificate database analysis for potential subdomains. If this 
							 really the case, select \"XX\" one more time!`)
			iloop ++
			readSelection(data, maxSelection)
		} else {
			iloop = 0
			return false
		}
	} else {
		//reader := bufio.NewReader(os.Stdin)
		//text, _ := reader.ReadString('\n')
		//text = strings.TrimSuffix(text, "\n")
		selection, err := strconv.Atoi(text)
		if err != nil {
			fmt.Printf("answer is invalid\n")
			readSelection(data, maxSelection)
		}
		if contains(selectionRange, selection) {
			// select url from data supplied
			for i := range data {
				log := data[i]
				if log.selectionNumber == selection {
					if log.status != "unavailable" {
						iloop ++
						grabCTLog("https://" + log.logValue)
					} else {
						fmt.Printf("log is unavailable\n")
						readSelection(data, maxSelection)
					}
				}
			}
		} else {
			fmt.Printf("select between 0-%d\n", maxSelection)
			readSelection(data, maxSelection)
		}
	}
	// ask user if he wants to download another round
	fmt.Printf("\rProgress: %s                    \n", "done")
	fmt.Println("Select another database or \"XX\" to exit.")
	iloop ++
	readSelection(data, maxSelection)
	return true // Never gets here...
}

// helper function to check membership of a number in a slice
func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

// helper function to make a slice of numbers
func makeRange(min, max int) []int {
	a := make([]int, max-min+1)
	for i := range a {
		a[i] = min + i
	}
	return a
}

// returns a list of all known certificate transparency log URLs
func returnKnownLogURLS() []string {
	var logUrls []string
	logData := grabKnownLogs("https://www.gstatic.com/ct/log_list/log_list.json")
	for i := range logData.Logs {
		log := logData.Logs[i]
		logUrls = append(logUrls, log.URL)
	}
	return logUrls
}

// downloads certificate transparency logs locally
func downloadCTLogs() {
	logs := returnKnownLogURLS()
	for i := range logs {
		grabCTLog("https://" + logs[i])
	}
}

// returns size of the certificate transparency log
func grabLogSize(URL string) (uint64, error) {
	var sthURL = URL + "ct/v1/get-sth"
	timeout := time.Duration(2 * time.Second)
	myClient := http.Client{
		Timeout: timeout,
	}
	resp, err := myClient.Get(sthURL)
	if err != nil {
		return uint64(0), err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return uint64(0), err
	}

	var sth ct.SignedTreeHead
	json.Unmarshal([]byte(body), &sth)
	return sth.TreeSize, err
}

// grabs subdomains from the supplied certificate transparency log
func grabCTLog(inputLog string) {
	fmt.Printf("Downloading %s\n", inputLog)
	logCount = 0
	size, err := grabLogSize(inputLog)
	if err != nil {
		printError("an error occurred")
	}
	logSize = size
	logClient, err := client.New(inputLog, &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, jsonclient.Options{UserAgent: "delator-scanner/1.2"})
	if err != nil {
		printError("an error occurred")
	}

	certRegex, precertRegex := createRegexes(".*")
	matcher, err := scanner.MatchSubjectRegex{
		CertificateSubjectRegex:    certRegex,
		PrecertificateSubjectRegex: precertRegex}, nil
	//if err != nil {
	//	printError("an error occurred")
	//}

	opts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     1000,
			ParallelFetch: 12,
			StartIndex:    0,
			EndIndex:      0,
		},
		Matcher:    matcher,
		NumWorkers: 12,
	}
	myScanner := scanner.NewScanner(logClient, opts)

	ctx := context.Background()
	myScanner.Scan(ctx, logCertInfo, logPrecertInfo)
}

// checks if local sqlite database exists
func databaseCheck() bool {
	if _, err := os.Stat("data.db"); err == nil {
		// do nothing, carry on
		return true // "TRUE" the database HAS BEEN created or checked!!
	} else if os.IsNotExist(err) {
		fmt.Printf("database missing, create one\n")
		if storeKnownLogs() == false {
			return true // "TRUE" the database HAS BEEN created or checked!!
		} else { return false }
	}
	return true
}

// reads subdomains from database
func readDatabase() {
	var id int
	var subdomain string
	database, _ := sql.Open("sqlite3", "./data.db")
	rows, err := database.Query("SELECT id, subdomain FROM subdomains")
	if err != nil {
		fmt.Println(err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&id, &subdomain)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(subdomain)
	}
	err = rows.Err()
	if err != nil {
		fmt.Println(err)
	}
	database.Close()
}

// reads subdomains from database
func queryDatabase(query string) []string {
	if databaseCheck() != true {
		fmt.Println("Certificate database has not been created for some reason ... ")
		return nil
	}
	if *outcsv != false {
		fmt.Printf("\r%s", "writing to csv")
	}
	var subdomains []string
	var id int
	var subdomain string
	database, _ := sql.Open("sqlite3", "./data.db")
	defer database.Close()

	rows, err := database.Query(fmt.Sprintf("SELECT id, subdomain FROM subdomains WHERE subdomain LIKE '%%%s%%'", query))
	if err != nil {
		fmt.Println(err)
	}
	defer rows.Close()
	for rows.Next() {
		err := rows.Scan(&id, &subdomain)
		if err != nil {
			fmt.Println(err)
		}
		subdomains = append(subdomains, subdomain)
	}
	err = rows.Err()
	if err != nil {
		fmt.Println(err)
	}
	return subdomains
}

// converts a list of subdomains into data struct objects
func normaliseDBData(inputData []string) (outputData []data) {
	for i := range inputData {
		var tmpData data
		tmpData.NameValue = inputData[i]
		outputData = append(outputData, tmpData)
	}
	return outputData
}

// sets up command-line arguments and default responses
func setup() bool {
	//newSet.Usage = func() {
	//	fmt.Printf(banner)
	//	fmt.Printf("\nwritten & maintained with ♥ by NetEvert\n\n")
	//	fmt.Println(utilDescription)
	//	newSet.PrintDefaults()
	//	os.Exit(1)
	//}

	//newSet.Parse(os.Args[1:])

	// workaround to suppress glog errors, as per https://github.com/kubernetes/kubernetes/issues/17162#issuecomment-225596212
	//flag.CommandLine.Parse([]string{})

	// check if user wants to download CT logs locally
	if *store {
		storeKnownLogs()
		//os.Exit(1)
		return true
	}

	// check if user wants to run version check
	//if *ver {
	//	fmt.Printf("DELATOR")
	//	fmt.Printf(" v.%s\n", appVersion)
	//	res, _ := latest.Check(githubTag, appVersion)
	//	if res.Outdated {
	//		fmt.Printf("v.%s available\n", res.Current)
	//	}
	//	os.Exit(1)
	//}

	// check if user has supplied domain
	if *domain == "" {
		fmt.Printf("\nplease supply a domain\n\n")
		fmt.Println(utilDescription)
		newSet.PrintDefaults()
		// os.Exit(1)
		return true
	}

	// check if user has supplied source
	if *source == "" {
		fmt.Printf("\nplease supply a source {db|crt}\n\n")
		fmt.Println(utilDescription)
		newSet.PrintDefaults()
		// os.Exit(1)
		return true
	}
	return false
}

// main program entry point
func CertSearch(targetDomain string, sourceReq string) bool {
	*source = sourceReq
	*domain = targetDomain

	setup()

	// mine data from crt.sh
	// if *source == "crt" {
	if sourceReq == "crt" {
		fmt.Println("Pulling Certificate Data from https://cert.sh for Subdomains for " + targetDomain + ".")
		// sanitizedDomain := sanitizedInput(*domain)
		sanitizedDomain := sanitizedInput(targetDomain)
		subdomains := fetchData(fmt.Sprintf("https://crt.sh/?q=%s&output=json", sanitizedDomain))
		if *resolve {
			printResults(extractSubdomains(subdomains))
		} else {
			printData(subdomains)
		}
		//os.Exit(1)
		return true
	}

	// mine data from local database
	// if *source == "db" {
	if sourceReq == "db" {
		fmt.Println("Pulling Certificate Database for Subdomains for " + targetDomain + ".")
		// sanitizedDomain := sanitizedInput(*domain)
		sanitizedDomain := sanitizedInput(targetDomain)
		if *resolve {
			printResults(queryDatabase(sanitizedDomain))
		} else {
			printData(normaliseDBData(queryDatabase(sanitizedDomain)))
		}
		//os.Exit(1)
		return false
	}

	// Check if user has supplied the correct source
	//if *source != "crt" || *source != "db" {
	//	//fmt.Printf("\ninvalid source [db|crt]\n\n")
	//	//fmt.Println(utilDescription)
	//	//newSet.PrintDefaults()
	//	// os.Exit(1)
	//	return false
	//}

	return false
}

