package searchscan

import (
	"bytes"
	"encoding/xml"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

 //Timestamp represents time as a UNIX timestamp in seconds.
type Timestamp time.Time

 //str2time converts a string containing a UNIX timestamp to to a time.Time.
func (t *Timestamp) str2time(s string) error {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*t = Timestamp(time.Unix(ts, 0))
	return nil
}

 //time2str formats the time.Time value as a UNIX timestamp string.
 //XXX these might also need to be changed to pointers. See str2time and UnmarshalXMLAttr.
func (t Timestamp) time2str() string {
	return strconv.FormatInt(time.Time(t).Unix(), 10)
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(t.time2str()), nil
}

func (t *Timestamp) UnmarshalJSON(b []byte) error {
	return t.str2time(string(b))
}

func (t Timestamp) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	return xml.Attr{Name: name, Value: t.time2str()}, nil
}

func (t *Timestamp) UnmarshalXMLAttr(attr xml.Attr) (err error) {
	return t.str2time(attr.Value)
}

//func (n *NmapRunner) UnmarshalNmapRun(attr xml.Attr) (err error) {
//	return n.nmapruns(attr.Value)
//}

// NmapRunner contains an array of NmapRun structs
type NmapRunner struct {
	NmapRuns []NmapRun `xml:"nmaprun" json:"nmaprun"`
}

// NmapRun is contains all the data for a single nmap scan.
type NmapRun struct {
	Scanner          string         `xml:"scanner,attr" json:"scanner"`
	Args             string         `xml:"args,attr" json:"args"`
	Start            Timestamp      `xml:"start,attr" json:"start"`
	StartStr         string         `xml:"startstr,attr" json:"startstr"`
	Version          string         `xml:"version,attr" json:"version"`
	ProfileName      string         `xml:"profile_name,attr" json:"profile_name"`
	XMLOutputVersion string         `xml:"xmloutputversion,attr" json:"xmloutputversion"`
	ScanInfo         ScanInfo       `xml:"scaninfo" json:"scaninfo"`
	Verbose          Verbose        `xml:"verbose" json:"verbose"`
	Debugging        Debugging      `xml:"debugging" json:"debugging"`
	TaskBegin        []Task         `xml:"taskbegin" json:"taskbegin"`
	TaskProgress     []TaskProgress `xml:"taskprogress" json:"taskprogress"`
	TaskEnd          []Task         `xml:"taskend" json:"taskend"`
	PreScripts       []Script       `xml:"prescript>script" json:"prescripts"`
	PostScripts      []Script       `xml:"postscript>script" json:"postscripts"`
	Hosts            []Host         `xml:"host" json:"hosts"`
	Targets          []Target       `xml:"target" json:"targets"`
	RunStats         RunStats       `xml:"runstats" json:"runstats"`
}

 //ScanInfo contains informational regarding how the scan was run.
type ScanInfo struct {
	Type        string `xml:"type,attr" json:"type"`
	Protocol    string `xml:"protocol,attr" json:"protocol"`
	NumServices int    `xml:"numservices,attr" json:"numservices"`
	Services    string `xml:"services,attr" json:"services"`
	ScanFlags   string `xml:"scanflags,attr" json:"scanflags"`
}

 //Verbose contains the verbosity level for the Nmap scan.
type Verbose struct {
	Level int `xml:"level,attr" json:"level"`
}

 //Debugging contains the debugging level for the Nmap scan.
type Debugging struct {
	Level int `xml:"level,attr" json:"level"`
}

 //Task contains information about started and stopped Nmap tasks.
type Task struct {
	Task      string    `xml:"task,attr" json:"task"`
	Time      Timestamp `xml:"time,attr" json:"time"`
	ExtraInfo string    `xml:"extrainfo,attr" json:"extrainfo"`
}

 //TaskProgress contains information about the progression of a Task.
type TaskProgress struct {
	Task      string    `xml:"task,attr" json:"task"`
	Time      Timestamp `xml:"time,attr" json:"time"`
	Percent   float32   `xml:"percent,attr" json:"percent"`
	Remaining int       `xml:"remaining,attr" json:"remaining"`
	Etc       Timestamp `xml:"etc,attr" json:"etc"`
}

 //Target is found in the Nmap xml spec. I have no idea what it actually is.
type Target struct {
	Specification string `xml:"specification,attr" json:"specification"`
	Status        string `xml:"status,attr" json:"status"`
	Reason        string `xml:"reason,attr" json:"reason"`
}

 //Host contains all information about a single host.
type Host struct {
	StartTime     Timestamp     `xml:"starttime,attr" json:"starttime"`
	EndTime       Timestamp     `xml:"endtime,attr" json:"endtime"`
	Comment       string        `xml:"comment,attr" json:"comment"`
	Status        Status        `xml:"status" json:"status"`
	Addresses     []Address     `xml:"address" json:"addresses"`
	Hostnames     []Hostname    `xml:"hostnames>hostname" json:"hostnames"`
	Smurfs        []Smurf       `xml:"smurf" json:"smurfs"`
	Ports         []Port        `xml:"ports>port" json:"ports"`
	ExtraPorts    []ExtraPorts  `xml:"ports>extraports" json:"extraports"`
	Os            Os            `xml:"os" json:"os"`
	Distance      Distance      `xml:"distance" json:"distance"`
	Uptime        Uptime        `xml:"uptime" json:"uptime"`
	TcpSequence   TcpSequence   `xml:"tcpsequence" json:"tcpsequence"`
	IpIdSequence  IpIdSequence  `xml:"ipidsequence" json:"ipidsequence"`
	TcpTsSequence TcpTsSequence `xml:"tcptssequence" json:"tcptssequence"`
	HostScripts   []Script      `xml:"hostscript>script" json:"hostscripts"`
	Trace         Trace         `xml:"trace" json:"trace"`
	Times         Times         `xml:"times" json:"times"`
}

 //Status is the host's status. Up, down, etc.
type Status struct {
	State     string  `xml:"state,attr" json:"state"`
	Reason    string  `xml:"reason,attr" json:"reason"`
	ReasonTTL float32 `xml:"reason_ttl,attr" json:"reason_ttl"`
}

 //Address contains a IPv4 or IPv6 address for a Host.
type Address struct {
	Addr     string `xml:"addr,attr" json:"addr"`
	AddrType string `xml:"addrtype,attr" json:"addrtype"`
	Vendor   string `xml:"vendor,attr" json:"vendor"`
}

 //Hostname is a single name for a Host.
type Hostname struct {
	Name string `xml:"name,attr" json:"name"`
	Type string `xml:"type,attr" json:"type"`
}

 //Smurf contains repsonses from a smurf attack. I think.
 //Smurf attacks, really?
type Smurf struct {
	Responses string `xml:"responses,attr" json:"responses"`
}

 //ExtraPorts contains the information about the closed|filtered ports.
type ExtraPorts struct {
	State   string   `xml:"state,attr" json:"state"`
	Count   int      `xml:"count,attr" json:"count"`
	Reasons []Reason `xml:"extrareasons" json:"reasons"`
}
type Reason struct {
	Reason string `xml:"reason,attr" json:"reason"`
	Count  int    `xml:"count,attr" json:"count"`
}

 //Port contains all the information about a scanned port.
type Port struct {
	Protocol string   `xml:"protocol,attr" json:"protocol"`
	PortId   int      `xml:"portid,attr" json:"id"`
	State    State    `xml:"state" json:"state"`
	Owner    Owner    `xml:"owner" json:"owner"`
	Service  Service  `xml:"service" json:"service"`
	Scripts  []Script `xml:"script" json:"scripts"`
}

 //State contains information about a given ports
 //status. State will be open, closed, etc.
type State struct {
	State     string  `xml:"state,attr" json:"state"`
	Reason    string  `xml:"reason,attr" json:"reason"`
	ReasonTTL float32 `xml:"reason_ttl,attr" json:"reason_ttl"`
	ReasonIP  string  `xml:"reason_ip,attr" json:"reason_ip"`
}

 //Owner contains the name of Port.Owner.
type Owner struct {
	Name string `xml:"name,attr" json:"name"`
}

 //Service contains detailed information about a Port's
 //service details.
type Service struct {
	Name       string `xml:"name,attr" json:"name"`
	Conf       int    `xml:"conf,attr" json:"conf"`
	Method     string `xml:"method,attr" json:"method"`
	Version    string `xml:"version,attr" json:"version"`
	Product    string `xml:"product,attr" json:"product"`
	ExtraInfo  string `xml:"extrainfo,attr" json:"extrainfo"`
	Tunnel     string `xml:"tunnel,attr" json:"tunnel"`
	Proto      string `xml:"proto,attr" json:"proto"`
	Rpcnum     string `xml:"rpcnum,attr" json:"rpcnum"`
	Lowver     string `xml:"lowver,attr" json:"lowver"`
	Highver    string `xml:"hiver,attr" json:"hiver"`
	Hostname   string `xml:"hostname,attr" json:"hostname"`
	OsType     string `xml:"ostype,attr" json:"ostype"`
	DeviceType string `xml:"devicetype,attr" json:"devicetype"`
	ServiceFp  string `xml:"servicefp,attr" json:"servicefp"`
	CPEs       []CPE  `xml:"cpe" json:"cpes"`
}

 //CPE (Common Platform Enumeration) is a standardized way to name software
 //applications, operating systems, and hardware platforms.
type CPE string

 //Script contains information from Nmap Scripting Engine.
type Script struct {
	Id       string    `xml:"id,attr" json:"id"`
	Output   string    `xml:"output,attr" json:"output"`
	Tables   []Table   `xml:"table" json:"tables"`
	Elements []Element `xml:"elem" json:"elements"`
}

 //Table contains the output of the script in a more parse-able form.
 //ToDo: This should be a map[string][]string
type Table struct {
	Key      string    `xml:"key,attr" json:"key"`
	Elements []Element `xml:"elem" json:"elements"`
	Table    []Table   `xml:"table" json:"tables"`
}

 //Element contains the output of the script, with detailed information
type Element struct {
	Key   string `xml:"key,attr" json:"key"`
	Value string `xml:",chardata" json:"value"`
}

 //Os contains the fingerprinted operating system for a Host.
type Os struct {
	PortsUsed      []PortUsed      `xml:"portused" json:"portsused"`
	OsMatches      []OsMatch       `xml:"osmatch" json:"osmatches"`
	OsFingerprints []OsFingerprint `xml:"osfingerprint" json:"osfingerprints"`
}

// PortUsed PortsUsed is the port used to fingerprint a Os.
type PortUsed struct {
	State  string `xml:"state,attr" json:"state"`
	Proto  string `xml:"proto,attr" json:"proto"`
	PortId int    `xml:"portid,attr" json:"portid"`
}

 //OsClass contains vendor information for an Os.
type OsClass struct {
	Vendor   string `xml:"vendor,attr" json:"vendor"`
	OsGen    string `xml:"osgen,attr"`
	Type     string `xml:"type,attr" json:"type"`
	Accuracy string `xml:"accurancy,attr" json:"accurancy"`
	OsFamily string `xml:"osfamily,attr" json:"osfamily"`
	CPEs     []CPE  `xml:"cpe" json:"cpes"`
}

 //OsMatch contains detailed information regarding a Os fingerprint.
type OsMatch struct {
	Name      string    `xml:"name,attr" json:"name"`
	Accuracy  string    `xml:"accuracy,attr" json:"accuracy"`
	Line      string    `xml:"line,attr" json:"line"`
	OsClasses []OsClass `xml:"osclass" json:"osclasses"`
}

 //OsFingerprint is the actual fingerprint string.
type OsFingerprint struct {
	Fingerprint string `xml:"fingerprint,attr" json:"fingerprint"`
}

 //Distance is the amount of hops to a particular host.
type Distance struct {
	Value int `xml:"value,attr" json:"value"`
}

 //Uptime is the amount of time the host has been up.
type Uptime struct {
	Seconds  int    `xml:"seconds,attr" json:"seconds"`
	Lastboot string `xml:"lastboot,attr" json:"lastboot"`
}

 //TcpSequence contains information regarding the detected tcp sequence.
type TcpSequence struct {
	Index      int    `xml:"index,attr" json:"index"`
	Difficulty string `xml:"difficulty,attr" json:"difficulty"`
	Values     string `xml:"vaules,attr" json:"vaules"`
}

 //Sequence contains information regarding the detected X sequence.
type Sequence struct {
	Class  string `xml:"class,attr" json:"class"`
	Values string `xml:"values,attr" json:"values"`
}
type IpIdSequence Sequence
type TcpTsSequence Sequence

 //Trace contains the hops to a Host.
type Trace struct {
	Proto string `xml:"proto,attr" json:"proto"`
	Port  int    `xml:"port,attr" json:"port"`
	Hops  []Hop  `xml:"hop" json:"hops"`
}

 //Hop is a ip hop to a Host.
type Hop struct {
	TTL    float32 `xml:"ttl,attr" json:"ttl"`
	RTT    float32 `xml:"rtt,attr" json:"rtt"`
	IPAddr string  `xml:"ipaddr,attr" json:"ipaddr"`
	Host   string  `xml:"host,attr" json:"host"`
}

 //Times contains time statistics for an Nmap scan.
type Times struct {
	SRTT string `xml:"srtt,attr" json:"srtt"`
	RTT  string `xml:"rttvar,attr" json:"rttv"`
	To   string `xml:"to,attr" json:"to"`
}

 //RunStats contains statistics for a
 //finished Nmap scan.
type RunStats struct {
	Finished Finished  `xml:"finished" json:"finished"`
	Hosts    HostStats `xml:"hosts" json:"hosts"`
}

 //Finished contains detailed statistics regarding
 //a finished Nmap scan.
type Finished struct {
	Time     Timestamp `xml:"time,attr" json:"time"`
	TimeStr  string    `xml:"timestr,attr" json:"timestr"`
	Elapsed  float32   `xml:"elapsed,attr" json:"elapsed"`
	Summary  string    `xml:"summary,attr" json:"summary"`
	Exit     string    `xml:"exit,attr" json:"exit"`
	ErrorMsg string    `xml:"errormsg,attr" json:"errormsg"`
}

 //HostStats contains the amount of up and down hosts and the total count.
type HostStats struct {
	Up    int `xml:"up,attr" json:"up"`
	Down  int `xml:"down,attr" json:"down"`
	Total int `xml:"total,attr" json:"total"`
}

 //Parse takes a byte array of nmap xml data and unmarshals it into an
 //NmapRun struct. All elements are returned as strings, it is up to the caller
 //to check and cast them to the proper type.
func Parse(content []byte) (*NmapRunner, error) {
	r := &NmapRunner{}
	err := xml.Unmarshal(content, r)
	return r, err
}

/*func NmapScan(ip string, fqdn string) []byte {
	var (
		resultBytes []byte
		errorBytes  []byte
	)
	fmt.Println("\n\n\nScanning " + fqdn + ": ")
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`
	s, err := nmap.NewScanner(
		nmap.WithTargets(ip),
		// nmap.WithPorts("1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389"),
		nmap.WithPorts("80,443,8080,25,110,111,53,5353,22,21,20,139,445"),
		nmap.WithServiceInfo(),
		// nmap.WithTimingTemplate(nmap.TimingSneaky),
		nmap.WithTimingTemplate(nmap.TimingNormal),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	// Executes asynchronously, allowing results to be streamed in real time.
	if err := s.RunAsync(); err != nil {
		panic(err)
	}

	// Connect to stdout of scanner.
	stdout := s.GetStdout()

	// Connect to stderr of scanner.
	stderr := s.GetStderr()

	// Goroutine to watch for stdout and print to screen. Additionally it stores
	// the bytes intoa variable for processiing later.
	go func() {
		for stdout.Scan() {
			fmt.Println(stdout.Text())
			resultBytes = append(resultBytes, stdout.Bytes()...)
		}
	}()
	// Goroutine to watch for stderr and print to screen. Additionally it stores
	// the bytes intoa variable for processiing later.
	go func() {
		for stderr.Scan() {
			errorBytes = append(errorBytes, stderr.Bytes()...)
		}
	}()

	// Blocks main until the scan has completed.
	if err := s.Wait(); err != nil {
		panic(err)
	}

	// Parsing the results into corresponding structs.
	result, err := nmap.Parse(resultBytes)

	// Parsing the results into the NmapError slice of our nmap Struct.
	result.NmapErrors = strings.Split(string(errorBytes), "\n")
	if err != nil {
		panic(err)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}
	return resultBytes
}*/

func DeepScan(target string, scan string, id string) {
	cmd := exec.Command("bash", "-c", "nmap " + scan)
	var out bytes.Buffer
	cmd.Stdout = &out
	err_ := cmd.Start()
	if err_ != nil {
		panic(err_)
	}
	err_ = cmd.Wait()
	if err_ != nil {
		panic(err_)
	}
	cleanNmapOutput(target,target + "-" + id + "-scan.xml")
	// Convert to HTML
	zn := target + "-" + id + "-scan.xml -o " + target + "-" + id + "-scan.html"
	cmd = exec.Command("bash", "-c", "xsltproc "+zn, os.Getenv("PATH"))
	err := cmd.Start()
	if err != nil {
		panic(err)
	}
	err = cmd.Wait()
	if err != nil {
		panic(err)
	}
}

func cleanNmapOutput(target string, filename string) {
	content, _ := ioutil.ReadFile(filename)
	str := string(content)
	str = str + "</nmaprun></nmaprunner>"
	str = strings.Replace(str, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprun><?xml-stylesheet href=\"file:///usr/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?>", "", -1)
	hstr := str[:0] + "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprunner><?xml-stylesheet href=\"file:///usr/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?><nmaprunner>" + str[0:]
	//hstr = hstr + "</xml>"
	//hstr = strings.Replace(hstr, "</nmaprun></xml>", "</nmaprun></nmaprunner>", -1)
	xf, _ := os.Create(target + "-" + time.Now().Format("20060102") + "-nmap-services-formatted.xml")
	_, err_ := xf.Write([]byte(hstr))
	if err_ != nil {
		panic(err_)
	}
	defer func(xf *os.File) {
		err := xf.Close()
		if err != nil {
			panic(err)
		}
	}(xf)
}

/*func CleanXML(target string, filename string) {
	content, _ := ioutil.ReadFile(filename)
	str := string(content)
	// Below is for Windows OS ////////////////////////////////////////////// DOESN'T WORK... or it will clean up so you can convert on Linux... //////////////
	// str = strings.Replace(str, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprun><?xml-stylesheet href=\"file:///C:/Program Files (x86)/Nmap/nmap.xsl\" type=\"text/xsl\"?>", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprunner><?xml-stylesheet href=\"/usr/share/nmap/nmap.xsl\" type=\"text/xsl\"?><nmaprunner>", -1)
	// Cleanup for Linux ///////////////////////////////////
	// str = strings.Replace(str, "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprun><?xml-stylesheet href=\"file:///C:/Program Files (x86)/Nmap/nmap.xsl\" type=\"text/xsl\"?>", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprunner><?xml-stylesheet href=\"/usr/share/nmap/nmap.xsl\" type=\"text/xsl\"?><nmaprunner>", -1)
	hstr := str[:0] + "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE nmaprunner><?xml-stylesheet href=\"file:///usr/bin/../share/nmap/nmap.xsl\" type=\"text/xsl\"?><nmaprunner>" + str[0:]
	hstr = hstr + "</xml>"
	hstr = strings.Replace(hstr, "</nmaprun></xml>", "</nmaprun></nmaprunner>", -1)
	xf, _ := os.Create(target + "-" + time.Now().Format("20060102") + "-nmap-services-formatted.xml")
	_, err_ := xf.Write([]byte(hstr))
	if err_ != nil {
		panic(err_)
	}
	defer func(xf *os.File) {
		err := xf.Close()
		if err != nil {
			panic(err)
		}
	}(xf)
}*/
