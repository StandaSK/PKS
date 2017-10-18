#include <vector>
#include <pcap.h>

struct arp {
	int operation;
	char text[64];
};

struct ethType {
	int value;
	char text[64];
};

struct icmp {
	int type;
	char text[64];
};

struct ipv4 {
	int protocol;
	char text[64];
};

struct tcp {
	int port;
	char text[64];
};

struct udp {
	int port;
	char text[64];
};

// Struktura na uchovavanie udajov zo suborov
struct definicie {
	std::vector<arp> arpVctr;
	std::vector<ethType> ethTypeVctr;
	std::vector<icmp> icmpVctr;
	std::vector<ipv4> ipv4Vctr;
	std::vector<tcp> tcpVctr;
	std::vector<udp> udpVctr;
};

// Struktura na uchovavanie ramcov
struct pkts {
	unsigned int poradie;
	pcap_pkthdr *header;
	unsigned char *data;
	struct pkts *next;
	struct pkts *prev;
};

// Struktura na uchovavanie IP adries a ich poctu odvysielanych bajtov
struct ipdata {
	unsigned long ip;
	int byteCount;
};

int getARPOperation(pkts *paket) {
	int operation = paket->data[20];
	operation = operation << 8;
	operation += paket->data[21];

	return operation;
}

int getEtherType(pkts *paket) {
	int value = paket->data[12];
	value = value << 8;
	value += paket->data[13];

	return value;
}

int getICMPType(pkts *paket) {
	return paket->data[34];
}

int getIPv4Protocol(pkts *paket) {
	return paket->data[23];
}

int getTCPSrcPort(pkts *paket) {
	int port = paket->data[34];
	port = port << 8;
	port += paket->data[35];

	return port;
}

int getTCPDstPort(pkts *paket) {
	int port = paket->data[36];
	port = port << 8;
	port += paket->data[37];

	return port;
}

int getUDPSrcPort(pkts *paket) {
	int port = paket->data[34];
	port = port << 8;
	port += paket->data[35];

	return port;
}

int getUDPDstPort(pkts *paket) {
	int port = paket->data[36];
	port = port << 8;
	port += paket->data[37];

	return port;
}

char* getARPOperationName(pkts *paket, definicie *def) {
	int i, operation = getARPOperation(paket);

	for (i = 0; i < (int) def->arpVctr.size(); i++) {
		if (def->arpVctr[i].operation == operation) {
			return def->arpVctr[i].text;
		}
	}

	return "N/A";
}

char* getEtherTypeName(pkts *paket, definicie *def) {
	int i, value = getEtherType(paket);

	for (i = 0; i < (int) def->ethTypeVctr.size(); i++) {
		if (def->ethTypeVctr[i].value == value) {
			return def->ethTypeVctr[i].text;
		}
	}

	return "N/A";
}

char* getICMPTypeName(pkts *paket, definicie *def) {
	int i, type = getICMPType(paket);

	for (i = 0; i < (int)def->icmpVctr.size(); i++) {
		if (def->icmpVctr[i].type == type) {
			return def->icmpVctr[i].text;
		}
	}

	return "N/A";
}

char* getIPv4ProtocolName(pkts *paket, definicie *def) {
	int i, protocol = getIPv4Protocol(paket);

	for (i = 0; i < (int) def->ipv4Vctr.size(); i++) {
		if (def->ipv4Vctr[i].protocol == protocol) {
			return def->ipv4Vctr[i].text;
		}
	}

	return "N/A";
}

char* getTCPSrcPortName(pkts *paket, definicie *def) {
	int i, port = getTCPSrcPort(paket);

	for (i = 0; i < (int) def->tcpVctr.size(); i++) {
		if (def->tcpVctr[i].port == port) {
			return def->tcpVctr[i].text;
		}
	}

	return "N/A";
}

char* getTCPDstPortName(pkts *paket, definicie *def) {
	int i, port = getTCPDstPort(paket);

	for (i = 0; i < (int) def->tcpVctr.size(); i++) {
		if (def->tcpVctr[i].port == port) {
			return def->tcpVctr[i].text;
		}
	}

	return "N/A";
}

char* getUDPSrcPortName(pkts *paket, definicie *def) {
	int i, port = getUDPSrcPort(paket);

	for (i = 0; i < (int) def->udpVctr.size(); i++) {
		if (def->udpVctr[i].port == port) {
			return def->udpVctr[i].text;
		}
	}

	return "N/A";
}

char* getUDPDstPortName(pkts *paket, definicie *def) {
	int i, port = getUDPDstPort(paket);

	for (i = 0; i < (int) def->udpVctr.size(); i++) {
		if (def->udpVctr[i].port == port) {
			return def->udpVctr[i].text;
		}
	}

	return "N/A";
}

bool isARP(pkts *paket, definicie *def) {
	if (strcmp(getEtherTypeName(paket, def), "ARP_(Address_Resolution_Protocol)") == 0)
		return true;

	return false;
}

bool isIPv4(pkts *paket, definicie *def) {
	if (strcmp(getEtherTypeName(paket, def), "Internet_IP_(IPv4)") == 0)
		return true;

	return false;
}

bool isICMP(pkts *paket, definicie *def) {
	if (isIPv4(paket, def) && (strcmp(getIPv4ProtocolName(paket, def), "ICMP") == 0))
		return true;

	return false;
}

bool isTCP(pkts *paket, definicie *def) {
	if (isIPv4(paket, def) && (strcmp(getIPv4ProtocolName(paket, def), "TCP") == 0))
		return true;

	return false;
}

bool isUDP(pkts *paket, definicie *def) {
	if (isIPv4(paket, def) && (strcmp(getIPv4ProtocolName(paket, def), "UDP") == 0))
		return true;

	return false;
}

unsigned long getARPSrcIP(pkts *paket) {
	unsigned char pole[4];

	for (int i = 0; i < 4; i++) {
		pole[i] = paket->data[28 + i];
	}

	return *(unsigned long *)pole;
}

unsigned long getARPDstIP(pkts *paket) {
	unsigned char pole[4];

	for (int i = 0; i < 4; i++) {
		pole[i] = paket->data[38 + i];
	}

	return *(unsigned long *)pole;
}

long long getARPSrcMAC(pkts *paket) {
	unsigned char pole[6];

	for (int i = 0; i < 6; i++) {
		pole[i] = paket->data[22 + i];
	}

	return *(long long *)pole;
}

long long getARPDstMAC(pkts *paket) {
	unsigned char pole[6];

	for (int i = 0; i < 6; i++) {
		pole[i] = paket->data[32 + i];
	}

	return *(long long *)pole;
}

unsigned long getIPv4SrcIP(pkts *paket) {
	unsigned char pole[4];

	for (int i = 0; i < 4; i++) {
		pole[i] = paket->data[26 + i];
	}

	return *(unsigned long *)pole;
}

unsigned long getIPv4DstIP(pkts *paket) {
	unsigned char pole[4];

	for (int i = 0; i < 4; i++) {
		pole[i] = paket->data[30 + i];
	}

	return *(unsigned long *)pole;
}

// Vypis IP adresy vsetkych vysielajucich uzlov, ako aj
// IP adresy uzla, ktory sumarne odvysielal najvacsi pocet bajtov
void vypisSrcIPadresy(pkts *prvy_paket, int packetCount, definicie *def) {
	pkts *akt = prvy_paket;
	ipdata *data = NULL;

	// Alokovanie pomocnej struktury
	data = (ipdata *)malloc(packetCount * sizeof(ipdata));

	// Inicializacia pomocnej struktury
	for (int i = 0; i < packetCount; i++) {
		data[i].byteCount = 0;
	}

	while (1) {
		unsigned long aktIP = getIPv4SrcIP(akt);

		for (int i = 0; i < packetCount; i++) {
			if (isIPv4(akt, def)) {
				if (data[i].byteCount == 0) {
					data[i].ip = aktIP;
					data[i].byteCount = akt->header->len;
					break;
				}
				if (data[i].ip == aktIP) {
					data[i].byteCount += akt->header->len;
					break;
				}
			}
		}

		if (akt->next != NULL) {
			akt = akt->next;
		}
		else {
			break;
		}
	}

	printf("IP adresy vysielajucich uzlov:\n");
	for (int i = 0; (data[i].byteCount != 0) && (i < packetCount); i++) {
		printf("%d.", data[i].ip & 0xFF);
		printf("%d.", data[i].ip >> 8 & 0xFF);
		printf("%d.", data[i].ip >> 16 & 0xFF);
		printf("%d\n", data[i].ip >> 24 & 0xFF);
	}

	int max = -1;
	unsigned long maxIP;
	printf("\nAdresa uzla s najvacsim poctom odvysielanych bajtov:\n");
	for (int i = 0; (data[i].byteCount != 0) && (i < packetCount); i++)
		if (data[i].byteCount > max) {
			max = data[i].byteCount;
			maxIP = data[i].ip;
		}

	printf("%d.", maxIP & 0xFF);
	printf("%d.", maxIP >> 8 & 0xFF);
	printf("%d.", maxIP >> 16 & 0xFF);
	printf("%d\t%d bajtov\n\n", maxIP >> 24 & 0xFF, max);
}

// Vypis udajov a obsahu konkretneho ramca
void vypis(pkts *paket) {
	printf("Ramec %d\n", paket->poradie);
	printf("Dlzka ramca poskytnuta pcap API - %d B\n", paket->header->len);
	if ((paket->header->len + 4) <= 64) {
		printf("Dlzka ramca prenasaneho po mediu - 64 B\n");
	}
	else printf("Dlzka ramca prenasaneho po mediu - %d B\n", paket->header->len + 4);

	if (paket->data[12] <= 0x06) {
		if (paket->data[14] == 0xAA) {
			printf("IEEE 802.3 LLC + SNAP\n");
		}
		else if (paket->data[14] == 0xFF) {
			printf("Novell 802.3 RAW\n");
		}
		else {
			printf("IEEE 802.3 LLC\n");
		}
	}
	else {
		printf("Ethernet II\n");
	}

	printf("Zdrojova MAC adresa: ");
	for (unsigned int i = 6; i < 12; i++) {
		printf("%.2x ", paket->data[i]);
	}
	putchar('\n');

	printf("Cielova MAC adresa: ");
	for (unsigned int i = 0; i < 6; i++) {
		printf("%.2x ", paket->data[i]);
	}
	putchar('\n');

	for (unsigned int i = 0; i < paket->header->caplen; i++) {
		if ((i % 16) == 0) printf("\n");
		if ((i % 16) == 8) printf(" ");
		printf("%.2x ", paket->data[i]);
	}

	printf("\n\n");
}

// Vypis prvych 10 a poslednych 10 ramcov
void vypis10(pkts *prvy_paket, pkts *last_paket, definicie *def) {
	pkts *aktualny = prvy_paket;

	if (last_paket->poradie < 20) {
		for (unsigned int i = 0; i < last_paket->poradie; i++) {
			vypis(aktualny);
			aktualny = aktualny->next;
		}
	}
	else {
		for (unsigned int i = 0; i < 10; i++) {
			vypis(aktualny);
			aktualny = aktualny->next;
		}

		aktualny = last_paket;

		for (unsigned int i = 0; i < 9; i++) {
			aktualny = aktualny->prev;
		}

		for (unsigned int i = 0; i < 10; i++) {
			vypis(aktualny);
			aktualny = aktualny->next;
		}
	}

	vypisSrcIPadresy(prvy_paket, last_paket->poradie, def);
}

// Vypis vsetkych komunikacii v subore
void vypisVsetko(pkts *prvy_paket, definicie *def) {
	pkts *akt = prvy_paket;

	while (1) {
		vypis(akt);

		if (akt->next != NULL) {
			akt = akt->next;
		}
		else {
			break;
		}
	}

	vypisSrcIPadresy(prvy_paket, akt->poradie, def);
}

// Vypis vsetkych ARP komunikacii
void vypisARPKomunikacii(pkts *prvy_paket, definicie *def) {
	pkts *akt = prvy_paket;
	int i = 1;

	while (1) {
		if (isARP(akt, def)) {
			char *operation = getARPOperationName(akt, def);

			printf("ARP-%s, ", operation);

			unsigned long dstIP = getARPDstIP(akt);

			if (strcmp(operation, "Request") == 0) {
				printf("IP adresa: %d.", dstIP & 0xFF);
				printf("%d.", dstIP >> 8 & 0xFF);
				printf("%d.", dstIP >> 16 & 0xFF);
				printf("%d,\t", dstIP >> 24 & 0xFF);

				printf("MAC adresa: ???\n");
			}
			else if (strcmp(operation, "Reply") == 0) {
				unsigned long srcIP = getARPSrcIP(akt);
				printf("IP: %d.", srcIP & 0xFF);
				printf("%d.", srcIP >> 8 & 0xFF);
				printf("%d.", srcIP >> 16 & 0xFF);
				printf("%d,\t", srcIP >> 24 & 0xFF);

				long long srcMAC = getARPSrcMAC(akt);
				printf("MAC adresa: %.2x ", (int)(srcMAC & 0xFF));
				printf("%.2x ", (int)(srcMAC >> 8 & 0xFF));
				printf("%.2x ", (int)(srcMAC >> 16 & 0xFF));
				printf("%.2x ", (int)(srcMAC >> 24 & 0xFF));
				printf("%.2x ", (int)(srcMAC >> 32 & 0xFF));
				printf("%.2x\n", (int)(srcMAC >> 40 & 0xFF));
			}

			unsigned long srcIP = getARPSrcIP(akt);
			printf("Zdrojova IP: %d.", srcIP & 0xFF);
			printf("%d.", srcIP >> 8 & 0xFF);
			printf("%d.", srcIP >> 16 & 0xFF);
			printf("%d,\t", srcIP >> 24 & 0xFF);

			printf("Cielova IP: %d.", dstIP & 0xFF);
			printf("%d.", dstIP >> 8 & 0xFF);
			printf("%d.", dstIP >> 16 & 0xFF);
			printf("%d\n", dstIP >> 24 & 0xFF);

			printf("Ramec %d\n", akt->poradie);
			printf("Dlzka ramca poskytnuta pcap API - %d B\n", akt->header->len);
			if ((akt->header->len + 4) <= 64) {
				printf("Dlzka ramca prenasaneho po mediu - 64 B\n");
			}
			else printf("Dlzka ramca prenasaneho po mediu - %d B\n", akt->header->len + 4);

			printf("Ethernet II\n");

			printf("Zdrojova MAC adresa: ");
			for (unsigned int i = 6; i < 12; i++) {
				printf("%.2x ", akt->data[i]);
			}
			putchar('\n');

			printf("Cielova MAC adresa: ");
			for (unsigned int i = 0; i < 6; i++) {
				printf("%.2x ", akt->data[i]);
			}
			putchar('\n');

			for (unsigned int i = 0; i < akt->header->caplen; i++) {
				if ((i % 16) == 0) printf("\n");
				if ((i % 16) == 8) printf(" ");
				printf("%.2x ", akt->data[i]);
			}

			printf("\n\n");

			/*if (strcmp(getARPOperationName(akt, def), "Request")) {
				pkts *pom = akt;

				while (1) {
					if (isARP(pom, def) && (strcmp(getARPOperationName(pom, def), "Reply") == 0) && (getARPDstIP(pom) == getARPSrcIP(akt)) && (getARPSrcIP(pom) == getARPDstIP(akt))) {
						printf("Komunikacia c.%d\n", i++);
						printf("ARP-Request, ");

						unsigned long dstIP = getARPDstIP(akt);
						printf("IP adresa: %d.", dstIP & 0xFF);
						printf("%d.", dstIP >> 8 & 0xFF);
						printf("%d.", dstIP >> 16 & 0xFF);
						printf("%d,\t", dstIP >> 24 & 0xFF);

						printf("MAC adresa: ???\n");

						unsigned long srcIP = getARPSrcIP(akt);
						printf("Zdrojova IP: %d.", srcIP & 0xFF);
						printf("%d.", srcIP >> 8 & 0xFF);
						printf("%d.", srcIP >> 16 & 0xFF);
						printf("%d,\t", srcIP >> 24 & 0xFF);

						printf("Cielova IP: %d.", dstIP & 0xFF);
						printf("%d.", dstIP >> 8 & 0xFF);
						printf("%d.", dstIP >> 16 & 0xFF);
						printf("%d\n", dstIP >> 24 & 0xFF);

						printf("Ramec %d\n", akt->poradie);
						printf("Dlzka ramca poskytnuta pcap API - %d B\n", akt->header->len);
						if ((akt->header->len + 4) <= 64) {
							printf("Dlzka ramca prenasaneho po mediu - 64 B\n");
						}
						else printf("Dlzka ramca prenasaneho po mediu - %d B\n", akt->header->len + 4);

						printf("Ethernet II\n");

						printf("Zdrojova MAC adresa: ");
						for (unsigned int i = 6; i < 12; i++) {
							printf("%.2x ", akt->data[i]);
						}
						putchar('\n');

						printf("Cielova MAC adresa: ");
						for (unsigned int i = 0; i < 6; i++) {
							printf("%.2x ", akt->data[i]);
						}
						putchar('\n');

						for (unsigned int i = 0; i < akt->header->caplen; i++) {
							if ((i % 16) == 0) printf("\n");
							if ((i % 16) == 8) printf(" ");
							printf("%.2x ", akt->data[i]);
						}

						printf("\n\n");

						printf("ARP-Reply, ");

						srcIP = getARPSrcIP(pom);
						printf("IP: %d.", srcIP & 0xFF);
						printf("%d.", srcIP >> 8 & 0xFF);
						printf("%d.", srcIP >> 16 & 0xFF);
						printf("%d,\t", srcIP >> 24 & 0xFF);
						
						long long srcMAC = getARPSrcMAC(pom);
						printf("MAC adresa: %.2x ", (int)(srcMAC & 0xFF));
						printf("%.2x ", (int)(srcMAC >> 8 & 0xFF));
						printf("%.2x ", (int)(srcMAC >> 16 & 0xFF));
						printf("%.2x ", (int)(srcMAC >> 24 & 0xFF));
						printf("%.2x ", (int)(srcMAC >> 32 & 0xFF));
						printf("%.2x\n", (int)(srcMAC >> 40 & 0xFF));

						srcIP = getARPSrcIP(pom);
						printf("Zdrojova IP: %d.", srcIP & 0xFF);
						printf("%d.", srcIP >> 8 & 0xFF);
						printf("%d.", srcIP >> 16 & 0xFF);
						printf("%d,\t", srcIP >> 24 & 0xFF);

						printf("Cielova IP: %d.", dstIP & 0xFF);
						printf("%d.", dstIP >> 8 & 0xFF);
						printf("%d.", dstIP >> 16 & 0xFF);
						printf("%d\n", dstIP >> 24 & 0xFF);

						printf("Ramec %d\n", pom->poradie);
						printf("Dlzka ramca poskytnuta pcap API - %d B\n", pom->header->len);
						if ((pom->header->len + 4) <= 64) {
							printf("Dlzka ramca prenasaneho po mediu - 64 B\n");
						}
						else printf("Dlzka ramca prenasaneho po mediu - %d B\n", pom->header->len + 4);

						printf("Ethernet II\n");

						printf("Zdrojova MAC adresa: ");
						for (unsigned int i = 6; i < 12; i++) {
							printf("%.2x ", pom->data[i]);
						}
						putchar('\n');

						printf("Cielova MAC adresa: ");
						for (unsigned int i = 0; i < 6; i++) {
							printf("%.2x ", pom->data[i]);
						}
						putchar('\n');

						for (unsigned int i = 0; i < pom->header->caplen; i++) {
							if ((i % 16) == 0) printf("\n");
							if ((i % 16) == 8) printf(" ");
							printf("%.2x ", pom->data[i]);
						}

						printf("\n\n");
					}

					if (pom->next != NULL) {
						pom = pom->next;
					}
					else {
						break;
					}
				}
			}*/
			
		}

		if (akt->next != NULL) {
			akt = akt->next;
		}
		else {
			break;
		}
	}
}

// Vypis vsetkych TCP komunikacii s 'text' portom
void vypisTCPKomunikacii(pkts *prvy_paket, char *text, definicie *def) {
	pkts *akt = prvy_paket;

	while (1) {
		if (isTCP(akt, def) && ((strcmp(getTCPSrcPortName(akt, def), text) == 0) || (strcmp(getTCPDstPortName(akt, def), text) == 0))) {
			printf("Ramec %d\n", akt->poradie);
			printf("Dlzka ramca poskytnuta pcap API - %d B\n", akt->header->len);
			if ((akt->header->len + 4) <= 64) {
				printf("Dlzka ramca prenasaneho po mediu - 64 B\n");
			}
			else printf("Dlzka ramca prenasaneho po mediu - %d B\n", akt->header->len + 4);

			printf("Ethernet II\n");

			printf("Zdrojova MAC adresa: ");
			for (unsigned int i = 6; i < 12; i++) {
				printf("%.2x ", akt->data[i]);
			}
			putchar('\n');

			printf("Cielova MAC adresa: ");
			for (unsigned int i = 0; i < 6; i++) {
				printf("%.2x ", akt->data[i]);
			}
			putchar('\n');

			printf("IPv4\n");

			unsigned long src = getIPv4SrcIP(akt);

			printf("Zdrojova IP adresa: ");
			printf("%d.", src & 0xFF);
			printf("%d.", src >> 8 & 0xFF);
			printf("%d.", src >> 16 & 0xFF);
			printf("%d\n", src >> 24 & 0xFF);

			unsigned long dst = getIPv4DstIP(akt);

			printf("Cielova IP adresa: ");
			printf("%d.", dst & 0xFF);
			printf("%d.", dst >> 8 & 0xFF);
			printf("%d.", dst >> 16 & 0xFF);
			printf("%d\n", dst >> 24 & 0xFF);

			printf("TCP\n");

			src = getTCPSrcPort(akt);
			printf("Zdrojovy port: %d\n", src);
			dst = getTCPDstPort(akt);
			printf("Cielovy port: %d\n", dst);

			for (unsigned int i = 0; i < akt->header->caplen; i++) {
				if ((i % 16) == 0) printf("\n");
				if ((i % 16) == 8) printf(" ");
				printf("%.2x ", akt->data[i]);
			}

			printf("\n\n");
		}

		if (akt->next != NULL) {
			akt = akt->next;
		}
		else {
			break;
		}
	}
}

// Vypis vsetkych UDP komunikacii s 'text' portom
void vypisUDPKomunikacii(pkts *prvy_paket, char *text, definicie *def) {
	pkts *akt = prvy_paket;

	while (1) {
		if (isUDP(akt, def) && ((strcmp(getUDPSrcPortName(akt, def), text) == 0) || (strcmp(getUDPDstPortName(akt, def), text) == 0))) {
			printf("Ramec %d\n", akt->poradie);
			printf("Dlzka ramca poskytnuta pcap API - %d B\n", akt->header->len);
			if ((akt->header->len + 4) <= 64) {
				printf("Dlzka ramca prenasaneho po mediu - 64 B\n");
			}
			else printf("Dlzka ramca prenasaneho po mediu - %d B\n", akt->header->len + 4);

			printf("Ethernet II\n");

			printf("Zdrojova MAC adresa: ");
			for (unsigned int i = 6; i < 12; i++) {
				printf("%.2x ", akt->data[i]);
			}
			putchar('\n');

			printf("Cielova MAC adresa: ");
			for (unsigned int i = 0; i < 6; i++) {
				printf("%.2x ", akt->data[i]);
			}
			putchar('\n');

			printf("IPv4\n");

			unsigned long src = getIPv4SrcIP(akt);

			printf("Zdrojova IP adresa: ");
			printf("%d.", src & 0xFF);
			printf("%d.", src >> 8 & 0xFF);
			printf("%d.", src >> 16 & 0xFF);
			printf("%d\n", src >> 24 & 0xFF);

			unsigned long dst = getIPv4DstIP(akt);

			printf("Cielova IP adresa: ");
			printf("%d.", dst & 0xFF);
			printf("%d.", dst >> 8 & 0xFF);
			printf("%d.", dst >> 16 & 0xFF);
			printf("%d\n", dst >> 24 & 0xFF);

			printf("UDP\n");

			src = getUDPSrcPort(akt);
			printf("Zdrojovy port: %d\n", src);
			dst = getUDPDstPort(akt);
			printf("Cielovy port: %d\n", dst);

			for (unsigned int i = 0; i < akt->header->caplen; i++) {
				if ((i % 16) == 0) printf("\n");
				if ((i % 16) == 8) printf(" ");
				printf("%.2x ", akt->data[i]);
			}

			printf("\n\n");
		}

		if (akt->next != NULL) {
			akt = akt->next;
		}
		else {
			break;
		}
	}
}

// Vypis vsetkych ICMP komunikacii
void vypisICMPKomunikacii(pkts *prvy_paket, definicie *def) {
	pkts *akt = prvy_paket;

	while (1) {
		if (isICMP(akt, def)) {
			printf("Ramec %d\n", akt->poradie);
			printf("Dlzka ramca poskytnuta pcap API - %d B\n", akt->header->len);
			if ((akt->header->len + 4) <= 64) {
				printf("Dlzka ramca prenasaneho po mediu - 64 B\n");
			}
			else printf("Dlzka ramca prenasaneho po mediu - %d B\n", akt->header->len + 4);

			printf("Ethernet II\n");

			printf("Zdrojova MAC adresa: ");
			for (unsigned int i = 6; i < 12; i++) {
				printf("%.2x ", akt->data[i]);
			}
			putchar('\n');

			printf("Cielova MAC adresa: ");
			for (unsigned int i = 0; i < 6; i++) {
				printf("%.2x ", akt->data[i]);
			}
			putchar('\n');

			printf("IPv4\n");

			unsigned long src = getIPv4SrcIP(akt);

			printf("Zdrojova IP adresa: ");
			printf("%d.", src & 0xFF);
			printf("%d.", src >> 8 & 0xFF);
			printf("%d.", src >> 16 & 0xFF);
			printf("%d\n", src >> 24 & 0xFF);

			unsigned long dst = getIPv4DstIP(akt);

			printf("Cielova IP adresa: ");
			printf("%d.", dst & 0xFF);
			printf("%d.", dst >> 8 & 0xFF);
			printf("%d.", dst >> 16 & 0xFF);
			printf("%d\n", dst >> 24 & 0xFF);

			printf("Typ ICMP spravy: %d - %s\n", getICMPType(akt), getICMPTypeName(akt, def));

			for (unsigned int i = 0; i < akt->header->caplen; i++) {
				if ((i % 16) == 0) printf("\n");
				if ((i % 16) == 8) printf(" ");
				printf("%.2x ", akt->data[i]);
			}

			printf("\n\n");
		}

		if (akt->next != NULL) {
			akt = akt->next;
		}
		else {
			break;
		}
	}
}

void vypisFTPdataRamcov(pkts *prvy_paket, definicie *def) {
	pkts *akt = prvy_paket;
	int pocet = 0;

	while (1) {
		if (isTCP(akt, def) && ((strcmp(getTCPDstPortName(akt, def), "ftp-data") == 0) || (strcmp(getTCPSrcPortName(akt, def), "ftp-data") == 0))) {
			vypis(akt);
			pocet++;
		}

		if (akt->next != NULL) {
			akt = akt->next;
		}
		else {
			printf("Pocet FTP-data ramcov v subore: %d\n", pocet);
			break;
		}
	}
}

// Vypis menu
void vypisMenu() {
	printf("Vyberte typ komunikacie na analyzu:\n");
	printf("a) HTTP komunikacie\n");
	printf("b) HTTPS komunikacie\n");
	printf("c) TELNET komunikacie\n");
	printf("d) SSH komunikacie\n");
	printf("e) FTP riadiace komunikacie\n");
	printf("f) FTP datove komunikacie\n");
	printf("g) Vsetky TFTP komunikacie\n");
	printf("h) Vsetky ICMP komunikacie\n");
	printf("i) Vsetky ARP dvojice\n");
	printf("j) Vsetky FTP-data ramce\n");
	printf("p) Vypis prvych 10 a poslednych 10 komunikacii zo suboru\n");
	printf("v) Vypis vsetkych komunikacii zo suboru\n");
	printf("x) Ukoncit program\n");
}

// Vlozi novy ramec do struktury ramcov
void insert(pkts **prvy_paket, pkts **last_paket, int poradie, pcap_pkthdr *header, const unsigned char *data) {
	pkts *novy = new pkts();
	novy->header = new pcap_pkthdr();
	novy->data = (unsigned char *) malloc (header->caplen * sizeof(unsigned char));
	novy->poradie = poradie;
	*(novy->header) = *header;
	novy->next = NULL;
	novy->prev = NULL;

	for (unsigned int i = 0; i < header->caplen; i++) {
		novy->data[i] = data[i];
	}

	if (*prvy_paket == NULL) {
		// Zoznam paketov je prazdny
		// Novy paket je priradeny na prve miesto zoznamu
		*prvy_paket = novy;
	}
	else {
		// Linkne novy paket na koniec zoznamu
		(*last_paket)->next = novy;
		novy->prev = *last_paket;
	}

	// Novy paket je priradeny na posledne miesto v zozname
	*last_paket = novy;
}

// Nacita definicie zo suborov
void nacitajDefinicie(definicie *def) {
	FILE *file;
	int cislo = 0;
	char text[64];

	file = fopen("definicie\\ARP.txt", "r");
	while (fscanf(file, "%d %s", &cislo, text) != EOF) {
		arp pom;
		pom.operation = cislo;
		strcpy(pom.text, text);
		def->arpVctr.push_back(pom);
	}

	file = fopen("definicie\\EtherType.txt", "r");
	while (fscanf(file, "%x %s", &cislo, text) != EOF) {
		ethType pom;
		pom.value = cislo;
		strcpy(pom.text, text);
		def->ethTypeVctr.push_back(pom);
	}

	file = fopen("definicie\\ICMP.txt", "r");
	while (fscanf(file, "%d %s", &cislo, text) != EOF) {
		icmp pom;
		pom.type = cislo;
		strcpy(pom.text, text);
		def->icmpVctr.push_back(pom);
	}

	file = fopen("definicie\\IPv4.txt", "r");
	while (fscanf(file, "%d %s", &cislo, text) != EOF) {
		ipv4 pom;
		pom.protocol = cislo;
		strcpy(pom.text, text);
		def->ipv4Vctr.push_back(pom);
	}

	file = fopen("definicie\\TCP.txt", "r");
	while (fscanf(file, "%d %s", &cislo, text) != EOF) {
		tcp pom;
		pom.port = cislo;
		strcpy(pom.text, text);
		def->tcpVctr.push_back(pom);
	}

	file = fopen("definicie\\UDP.txt", "r");
	while (fscanf(file, "%d %s", &cislo, text) != EOF) {
		udp pom;
		pom.port = cislo;
		strcpy(pom.text, text);
		def->udpVctr.push_back(pom);
	}
}

int main() {
	//char nazov_suboru[] = "vzorky_pcap_na_analyzu\\trace-2.pcap";		// Tu je aj 802.3 LLC
	//char nazov_suboru[] = "vzorky_pcap_na_analyzu\\trace-3.pcap";		// Toto je maly subor (17 ramcov)
	//char nazov_suboru[] = "vzorky_pcap_na_analyzu\\trace-16.pcap";	// Toto je pamatovo najvacsi subor
	//char nazov_suboru[] = "vzorky_pcap_na_analyzu\\trace-23.pcap";	// Tu je 802.3 RAW
	//char nazov_suboru[] = "vzorky_pcap_na_analyzu\\eth-8.pcap";			// Toto je pamatovo najmensi subor
	char nazov_suboru[] = "vzorky_pcap_na_analyzu\\trace-14.pcap";
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t *pakety = pcap_open_offline(nazov_suboru, errbuff);
	pcap_pkthdr *header;
	const unsigned char* data;
	char volba;
	unsigned int packetCount = 0;
	pkts *prvy_paket = NULL, *last_paket = NULL;
	definicie *def = new definicie();
	
	nacitajDefinicie(def);

	if (pakety == NULL) {
		printf("Nepodarilo sa otvorit .pcap subor!\nPre ukoncenie programu stlacte klavesu Enter.");
		getchar();
		return -1;
	}

	// Nacitanie ramcov zo suboru
	while (pcap_next_ex(pakety, &header, &data) >= 0) {
		packetCount++;
		insert(&prvy_paket, &last_paket, packetCount, header, data);
	}

	vypisMenu();

	while (volba = getchar()) {
		getchar();	// Preskocenie znaku '\n'

		switch (volba) {
		case 'a':
			vypisTCPKomunikacii(prvy_paket, "http", def);
			break;
		case 'b':
			vypisTCPKomunikacii(prvy_paket, "https", def);
			break;
		case 'c':
			vypisTCPKomunikacii(prvy_paket, "telnet", def);
			break;
		case 'd':
			vypisTCPKomunikacii(prvy_paket, "ssh", def);
			break;
		case 'e':
			vypisTCPKomunikacii(prvy_paket, "ftp-control", def);
			break;
		case 'f':
			vypisTCPKomunikacii(prvy_paket, "ftp-data", def);
			break;
		case 'g':
			vypisUDPKomunikacii(prvy_paket, "tftp", def);
			break;
		case 'h':
			vypisICMPKomunikacii(prvy_paket, def);
			break;
		case 'i':
			vypisARPKomunikacii(prvy_paket, def);
			break;
		case 'j':
			vypisFTPdataRamcov(prvy_paket, def);
			break;
		case 'p':
			vypis10(prvy_paket, last_paket, def);
			break;
		case 'v':
			vypisVsetko(prvy_paket, def);
			break;
		case 'x':
			return 0;
		default:
			printf("Znak \"%c\" nie je platnou volbou!\n", volba);
			break;
		}

		vypisMenu();
	}

	return 0;
}