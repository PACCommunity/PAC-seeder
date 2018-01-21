#include <algorithm>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include "bitcoin.h"
#include "db.h"

using namespace std;

bool fTestNet = false;

class CDnsSeedOpts {
public:
  int nThreads;
  int nPort;
  int nDnsThreads;
  int fUseTestNet;
  int fWipeBan;
  int fWipeIgnore;
  const char *mbox;
  const char *ns;
  const char *host;
  const char *tor;
  const char *ipv4_proxy;
  const char *ipv6_proxy;

  CDnsSeedOpts() : nThreads(96), nDnsThreads(4), nPort(53), mbox(NULL), ns(NULL), host(NULL), tor(NULL), fUseTestNet(false), fWipeBan(false), fWipeIgnore(false), ipv4_proxy(NULL), ipv6_proxy(NULL) {}

  void ParseCommandLine(int argc, char **argv) {
    static const char *help = "PACcoin-seeder\n"
                              "Usage: %s -h <host> -n <ns> [-m <mbox>] [-t <threads>] [-p <port>]\n"
                              "\n"
                              "Options:\n"
                              "-h <host>       Hostname of the DNS seed\n"
                              "-n <ns>         Hostname of the nameserver\n"
                              "-m <mbox>       E-Mail address reported in SOA records\n"
                              "-t <threads>    Number of crawlers to run in parallel (default 96)\n"
                              "-d <threads>    Number of DNS server threads (default 4)\n"
                              "-p <port>       UDP port to listen on (default 53)\n"
                              "-o <ip:port>    Tor proxy IP/Port\n"
                              "-i <ip:port>    IPV4 SOCKS5 proxy IP/Port\n"
                              "-k <ip:port>    IPV6 SOCKS5 proxy IP/Port\n"
                              "--testnet       Use testnet\n"
                              "--wipeban       Wipe list of banned nodes\n"
                              "--wipeignore    Wipe list of ignored nodes\n"
                              "-?, --help      Show this text\n"
                              "\n";
    bool showHelp = false;

    while(1) {
      static struct option long_options[] = {
        {"host", required_argument, 0, 'h'},
        {"ns",   required_argument, 0, 'n'},
        {"mbox", required_argument, 0, 'm'},
        {"threads", required_argument, 0, 't'},
        {"dnsthreads", required_argument, 0, 'd'},
        {"port", required_argument, 0, 'p'},
        {"onion", required_argument, 0, 'o'},
        {"proxyipv4", required_argument, 0, 'i'},
        {"proxyipv6", required_argument, 0, 'k'},
        {"testnet", no_argument, &fUseTestNet, 1},
        {"wipeban", no_argument, &fWipeBan, 1},
        {"wipeignore", no_argument, &fWipeBan, 1},
        {"help", no_argument, 0, '?'},
        {0, 0, 0, 0}
      };
      int option_index = 0;
      int c = getopt_long(argc, argv, "h:n:m:t:p:d:o:i:k:?", long_options, &option_index);
      if (c == -1) break;
      switch (c) {
        case 'h': {
          host = optarg;
          break;
        }

        case 'm': {
          mbox = optarg;
          break;
        }

        case 'n': {
          ns = optarg;
          break;
        }

        case 't': {
          int n = strtol(optarg, NULL, 10);
          if (n > 0 && n < 1000) nThreads = n;
          break;
        }

        case 'd': {
          int n = strtol(optarg, NULL, 10);
          if (n > 0 && n < 1000) nDnsThreads = n;
          break;
        }

        case 'p': {
          int p = strtol(optarg, NULL, 10);
          if (p > 0 && p < 65536) nPort = p;
          break;
        }

        case 'o': {
          tor = optarg;
          break;
        }

        case 'i': {
          ipv4_proxy = optarg;
          break;
        }

        case 'k': {
          ipv6_proxy = optarg;
          break;
        }

        case '?': {
          showHelp = true;
          break;
        }
      }
    }
    if (host != NULL && ns == NULL) showHelp = true;
    if (showHelp) {
        fprintf(stderr, help, argv[0]);
        exit(0);
    }
  }
};

extern "C" {
#include "dns.h"
}

CAddrDb db;

extern "C" void* ThreadCrawler(void* data) {
  int *nThreads=(int*)data;
  do {
    std::vector<CServiceResult> ips;
    int wait = 5;
    db.GetMany(ips, 16, wait);
    int64 now = time(NULL);
    if (ips.empty()) {
      wait *= 1000;
      wait += rand() % (500 * *nThreads);
      Sleep(wait);
      continue;
    }
    vector<CAddress> addr;
    for (int i=0; i<ips.size(); i++) {
      CServiceResult &res = ips[i];
      res.nBanTime = 0;
      res.nClientV = 0;
      res.nHeight = 0;
      res.strClientV = "";
      bool getaddr = res.ourLastSuccess + 86400 < now;
      res.fGood = TestNode(res.service,res.nBanTime,res.nClientV,res.strClientV,res.nHeight,getaddr ? &addr : NULL);
    }
    db.ResultMany(ips);
    db.Add(addr);
  } while(1);
}

extern "C" int GetIPList(void *thread, addr_t *addr, int max, int ipv4, int ipv6);

class CDnsThread {
public:
  dns_opt_t dns_opt; // must be first
  const int id;
  vector<addr_t> cache;
  int nIPv4, nIPv6;
  time_t cacheTime;
  unsigned int cacheHits;
  uint64_t dbQueries;

  void cacheHit(bool force = false) {
    static bool nets[NET_MAX] = {};
    if (!nets[NET_IPV4]) {
        nets[NET_IPV4] = true;
        nets[NET_IPV6] = true;
    }
    time_t now = time(NULL);
    cacheHits++;
    if (force || cacheHits > (cache.size()*cache.size()/400) || (cacheHits*cacheHits > cache.size() / 20 && (now - cacheTime > 5))) {
      set<CNetAddr> ips;
      db.GetIPs(ips, 1000, nets);
      dbQueries++;
      cache.clear();
      nIPv4 = 0;
      nIPv6 = 0;
      cache.reserve(ips.size());
      for (set<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
        struct in_addr addr;
        struct in6_addr addr6;
        if ((*it).GetInAddr(&addr)) {
          addr_t a;
          a.v = 4;
          memcpy(&a.data.v4, &addr, 4);
          cache.push_back(a);
          nIPv4++;
        } else if ((*it).GetIn6Addr(&addr6)) {
          addr_t a;
          a.v = 6;
          memcpy(&a.data.v6, &addr6, 16);
          cache.push_back(a);
          nIPv6++;
        }
      }
      cacheHits = 0;
      cacheTime = now;
    }
  }

  CDnsThread(CDnsSeedOpts* opts, int idIn) : id(idIn) {
    dns_opt.host = opts->host;
    dns_opt.ns = opts->ns;
    dns_opt.mbox = opts->mbox;
    dns_opt.datattl = 60;
    dns_opt.nsttl = 40000;
    dns_opt.cb = GetIPList;
    dns_opt.port = opts->nPort;
    dns_opt.nRequests = 0;
    cache.clear();
    cache.reserve(1000);
    cacheTime = 0;
    cacheHits = 0;
    dbQueries = 0;
    nIPv4 = 0;
    nIPv6 = 0;
    cacheHit(true);
  }

  void run() {
    dnsserver(&dns_opt);
  }
};

extern "C" int GetIPList(void *data, addr_t* addr, int max, int ipv4, int ipv6) {
  CDnsThread *thread = (CDnsThread*)data;
  thread->cacheHit();
  unsigned int size = thread->cache.size();
  unsigned int maxmax = (ipv4 ? thread->nIPv4 : 0) + (ipv6 ? thread->nIPv6 : 0);
  if (max > size)
    max = size;
  if (max > maxmax)
    max = maxmax;
  int i=0;
  while (i<max) {
    int j = i + (rand() % (size - i));
    do {
        bool ok = (ipv4 && thread->cache[j].v == 4) ||
                  (ipv6 && thread->cache[j].v == 6);
        if (ok) break;
        j++;
        if (j==size)
            j=i;
    } while(1);
    addr[i] = thread->cache[j];
    thread->cache[j] = thread->cache[i];
    thread->cache[i] = addr[i];
    i++;
  }
  return max;
}

vector<CDnsThread*> dnsThread;

extern "C" void* ThreadDNS(void* arg) {
  CDnsThread *thread = (CDnsThread*)arg;
  thread->run();
}

int StatCompare(const CAddrReport& a, const CAddrReport& b) {
  if (a.uptime[4] == b.uptime[4]) {
    if (a.uptime[3] == b.uptime[3]) {
      return a.clientVersion > b.clientVersion;
    } else {
      return a.uptime[3] > b.uptime[3];
    }
  } else {
    return a.uptime[4] > b.uptime[4];
  }
}

extern "C" void* ThreadDumper(void*) {
  int count = 0;
  do {
    Sleep(100000 << count); // First 100s, than 200s, 400s, 800s, 1600s, and then 3200s forever
    if (count < 5)
        count++;
    {
      vector<CAddrReport> v = db.GetAll();
      sort(v.begin(), v.end(), StatCompare);
      FILE *f = fopen("dnsseed.dat.new","w+");
      if (f) {
        {
          CAutoFile cf(f);
          cf << db;
        }
        rename("dnsseed.dat.new", "dnsseed.dat");
      }
      FILE *d = fopen("dnsseed.dump", "w");
      fprintf(d, "# address                                        good  lastSuccess    %%(2h)   %%(8h)   %%(1d)   %%(7d)  %%(30d)  blocks      svcs  version\n");
      double stat[5]={0,0,0,0,0};
      for (vector<CAddrReport>::const_iterator it = v.begin(); it < v.end(); it++) {
        CAddrReport rep = *it;
        fprintf(d, "%-47s  %4d  %11"PRId64"  %6.2f%% %6.2f%% %6.2f%% %6.2f%% %6.2f%%  %6i  %08"PRIx64"  %5i \"%s\"\n", rep.ip.ToString().c_str(), (int)rep.fGood, rep.lastSuccess, 100.0*rep.uptime[0], 100.0*rep.uptime[1], 100.0*rep.uptime[2], 100.0*rep.uptime[3], 100.0*rep.uptime[4], rep.blocks, rep.services, rep.clientVersion, rep.clientSubVersion.c_str());
        stat[0] += rep.uptime[0];
        stat[1] += rep.uptime[1];
        stat[2] += rep.uptime[2];
        stat[3] += rep.uptime[3];
        stat[4] += rep.uptime[4];
      }
      fclose(d);
      FILE *ff = fopen("dnsstats.log", "a");
      fprintf(ff, "%llu %g %g %g %g %g\n", (unsigned long long)(time(NULL)), stat[0], stat[1], stat[2], stat[3], stat[4]);
      fclose(ff);
    }
  } while(1);
}

extern "C" void* ThreadStats(void*) {
  bool first = true;
  do {
    char c[256];
    time_t tim = time(NULL);
    struct tm *tmp = localtime(&tim);
    strftime(c, 256, "[%y-%m-%d %H:%M:%S]", tmp);
    CAddrDbStats stats;
    db.GetStats(stats);
    if (first)
    {
      first = false;
      printf("\n\n\n\x1b[3A");
    }
    else
      printf("\x1b[2K\x1b[u");
    printf("\x1b[s");
    uint64_t requests = 0;
    uint64_t queries = 0;
    for (unsigned int i=0; i<dnsThread.size(); i++) {
      requests += dnsThread[i]->dns_opt.nRequests;
      queries += dnsThread[i]->dbQueries;
    }
    printf("%s %i/%i available (%i tried in %is, %i new, %i active), %i banned; %llu DNS requests, %llu db queries", c, stats.nGood, stats.nAvail, stats.nTracked, stats.nAge, stats.nNew, stats.nAvail - stats.nTracked - stats.nNew, stats.nBanned, (unsigned long long)requests, (unsigned long long)queries);
    Sleep(1000);
  } while(1);
}

static const string mainnet_seeds[] = {"104.162.29.177","107.189.41.252","107.189.41.253","110.141.197.253",
                                        "113.234.210.42","119.35.239.10","121.141.1.110","124.190.20.196",
                                        "13.59.176.178","138.75.82.49","142.196.81.147","145.133.26.125",
                                        "173.208.164.34","174.65.5.243","175.156.208.93","177.134.72.187",
                                        "178.202.104.208","179.105.110.4","181.63.77.204","186.219.65.154",
                                        "187.183.89.32","187.59.22.213","188.193.115.1","188.221.66.158",
                                        "188.230.13.244","189.73.237.8","191.223.56.136","198.91.208.190",
                                        "200.101.11.208","200.163.153.67","201.40.6.249","201.43.133.12",
                                        "212.187.125.158","213.114.93.152","213.239.208.169","213.49.231.63",
                                        "213.49.248.83","213.89.70.19","24.12.255.181","34.214.105.83",
                                        "37.135.53.123","39.59.132.132","42.150.237.167","50.38.44.218",
                                        "54.200.21.73","54.202.194.41","54.202.91.1","54.244.11.199",
                                        "59.102.126.50","59.8.9.39","60.21.2.42","67.164.169.35",
                                        "67.230.58.25","67.246.149.154","68.36.216.167","68.48.225.122",
                                        "70.161.211.48","71.201.209.44","72.185.23.235","73.223.25.90",
                                        "73.237.34.82","75.148.236.42","77.54.197.131","78.26.164.192",
                                        "80.64.131.249","84.165.226.164","85.10.208.71","88.164.75.41",
                                        "91.203.26.132","92.0.227.118","93.75.81.205","93.80.28.78",
                                        "96.87.95.52","97.92.217.92","98.180.124.103","98.213.69.205",
                                        "98.213.69.205", ""};
static const string testnet_seeds[] = {"", ""};
static const string *seeds = mainnet_seeds;

extern "C" void* ThreadSeeder(void*) {
  do {
    for (int i=0; seeds[i] != ""; i++) {
      vector<CNetAddr> ips;
      LookupHost(seeds[i].c_str(), ips);
      for (vector<CNetAddr>::iterator it = ips.begin(); it != ips.end(); it++) {
        db.Add(CService(*it, GetDefaultPort()), true);
      }
    }
    Sleep(1800000);
  } while(1);
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  setbuf(stdout, NULL);
  CDnsSeedOpts opts;
  opts.ParseCommandLine(argc, argv);
  if (opts.tor) {
    CService service(opts.tor, 9050);
    if (service.IsValid()) {
      printf("Using Tor proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_TOR, service);
    }
  }
  if (opts.ipv4_proxy) {
    CService service(opts.ipv4_proxy, 9050);
    if (service.IsValid()) {
      printf("Using IPv4 proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_IPV4, service);
    }
  }
  if (opts.ipv6_proxy) {
    CService service(opts.ipv6_proxy, 9050);
    if (service.IsValid()) {
      printf("Using IPv6 proxy at %s\n", service.ToStringIPPort().c_str());
      SetProxy(NET_IPV6, service);
    }
  }
  bool fDNS = true;
  if (opts.fUseTestNet) {
      printf("Using testnet.\n");
      pchMessageStart[0] = 0xcd;
      pchMessageStart[1] = 0xf2;
      pchMessageStart[2] = 0xc0;
      pchMessageStart[3] = 0xef;
      seeds = testnet_seeds;
      fTestNet = true;
  }
  if (!opts.ns) {
    printf("No nameserver set. Not starting DNS server.\n");
    fDNS = false;
  }
  if (fDNS && !opts.host) {
    fprintf(stderr, "No hostname set. Please use -h.\n");
    exit(1);
  }
  if (fDNS && !opts.mbox) {
    fprintf(stderr, "No e-mail address set. Please use -m.\n");
    exit(1);
  }
  FILE *f = fopen("dnsseed.dat","r");
  if (f) {
    printf("Loading dnsseed.dat...");
    CAutoFile cf(f);
    cf >> db;
    if (opts.fWipeBan)
        db.banned.clear();
    if (opts.fWipeIgnore)
        db.ResetIgnores();
    printf("done\n");
  }
  pthread_t threadDns, threadSeed, threadDump, threadStats;
  if (fDNS) {
    printf("Starting %i DNS threads for %s on %s (port %i)...", opts.nDnsThreads, opts.host, opts.ns, opts.nPort);
    dnsThread.clear();
    for (int i=0; i<opts.nDnsThreads; i++) {
      dnsThread.push_back(new CDnsThread(&opts, i));
      pthread_create(&threadDns, NULL, ThreadDNS, dnsThread[i]);
      printf(".");
      Sleep(20);
    }
    printf("done\n");
  }
  printf("Starting seeder...");
  pthread_create(&threadSeed, NULL, ThreadSeeder, NULL);
  printf("done\n");
  printf("Starting %i crawler threads...", opts.nThreads);
  pthread_attr_t attr_crawler;
  pthread_attr_init(&attr_crawler);
  pthread_attr_setstacksize(&attr_crawler, 0x20000);
  for (int i=0; i<opts.nThreads; i++) {
    pthread_t thread;
    pthread_create(&thread, &attr_crawler, ThreadCrawler, &opts.nThreads);
  }
  pthread_attr_destroy(&attr_crawler);
  printf("done\n");
  pthread_create(&threadStats, NULL, ThreadStats, NULL);
  pthread_create(&threadDump, NULL, ThreadDumper, NULL);
  void* res;
  pthread_join(threadDump, &res);
  return 0;
}
