// Zadanie 2 - Pocitacove a komunikacne systemy
// Stanislav Jakubek, utorok 18:00, PU1

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>

#pragma comment(lib, "Ws2_32.lib")

struct header {
	unsigned long poradie;
	unsigned long total;
	unsigned long dlzka;
	unsigned long checksum;
	unsigned long flags;

#define ACK 0xfff00fff
#define KPALV 0x0f0f0f00
#define KPALVRSPNS 0xf0f0f000
};

struct packet {
	unsigned long dlzka;
	unsigned char *data;
};

#define debug 0

#define port 8086
#define maxSize 5000
#define polynom 0xedb88320
#define socket_timeout_sec 2
#define headerSize sizeof(header)
#define capsuleSize sizeof(unsigned short) + headerSize

// Cyclic redundancy check
unsigned long crc32b(const unsigned char *data, unsigned long dlzka) {
	unsigned long i, result = 0xFFFFFFFF;

	while (dlzka--) {
		result ^= *data++;
		for (i = 0; i < 8; i++) {
			if (result & 1) {
				result = (result >> 1) ^ polynom;
			}
			else {
				result = result >> 1;
			}
		}
	}

	return ~result;
}

// Obali data hlavickou
packet *enkapsulacia(header hlavicka, packet *data) {
	packet *final = (packet *) malloc (sizeof(packet));
	final->dlzka = (unsigned short) headerSize + data->dlzka;

	// Tvorba hlavicky paketu
	final->data = (unsigned char *) malloc (final->dlzka);
	((header *) final->data)->poradie = hlavicka.poradie;
	((header *) final->data)->total = hlavicka.total;
	((header *) final->data)->dlzka = data->dlzka;
	((header *) final->data)->checksum = 0;
	((header *) final->data)->flags = hlavicka.flags;

	// Prekopirovanie udajov do paketu
	memcpy((unsigned char *) (final->data + headerSize), data->data, data->dlzka);

	// Checksum
	((header *) final->data)->checksum = crc32b(final->data, headerSize + data->dlzka);

	if (debug) {
		printf("Enkapsulacia dat dlzky %lu\n", data->dlzka);
		printf("Poradie: %lu/%lu\n", ((header *)final->data)->poradie, ((header *)final->data)->total);
		printf("Dlzka dat (z hlavicky): %lu\n", ((header *)final->data)->dlzka);
		printf("Checksum: %lu\n", ((header *)final->data)->checksum);
		printf("Flags: %lu\n", ((header *)final->data)->flags);
		printf("Dlzka paketu: %lu\n", final->dlzka);
		printf("Sprava: %.*s\n", data->dlzka, data->data);
	}

	return final;
}

// Z paketu overi checksum, vytiahne data
packet *deenkapsulacia(header *hlavicka, packet *data) {
	packet *final = (packet *) malloc (sizeof(packet));
	
	// Kontrola checksum
	unsigned long checksum = ((header *) data->data)->checksum;
	((header *) data->data)->checksum = 0;
	unsigned long vygenerovany_checksum = crc32b(data->data, data->dlzka);
	if (checksum != vygenerovany_checksum) {
		if (debug) {
			printf("Checksum pri deenkapsulacii nesedi!\n");
			printf("Z paketu: %lu\nVygenerovany: %lu\n", checksum, vygenerovany_checksum);
		}
		return NULL;
	}

	// Ziskanie udajov z hlavicky
	hlavicka->poradie = ((header *) data->data)->poradie;
	hlavicka->total = ((header *) data->data)->total;
	hlavicka->flags = ((header *) data->data)->flags;
	hlavicka->checksum = checksum;
	hlavicka->dlzka = ((header *)data->data)->dlzka;
	final->dlzka = ((header *) data->data)->dlzka;

	// Prekopirovanie udajov do paketu
	final->data = (unsigned char *) malloc (final->dlzka);
	memcpy(final->data, (unsigned char *)(data->data + headerSize), final->dlzka);

	if (debug) {
		printf("Deenkapsulacia spravy dlzky %lu\n", data->dlzka);
		printf("Poradie: %lu/%lu\n", hlavicka->poradie, hlavicka->total);
		printf("Dlzka dat (z hlavicky): %lu\n", hlavicka->dlzka);
		printf("Checksum z paketu: %lu\nVygenerovany: %lu\n", hlavicka->checksum, vygenerovany_checksum);
		printf("Flags: %lu\n", hlavicka->flags);
		printf("Dlzka paketu: %lu\n", final->dlzka);
		printf("Sprava: %.*s\n", hlavicka->dlzka, final->data);
	}

	return final;
}

// Spusti prijimac
int prijimac() {
	int initError;

	WSADATA wsaData;
	SOCKET udpsocket = INVALID_SOCKET;
	SOCKADDR_IN recv_addr;

	initError = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (initError != NO_ERROR) {
		printf("Zlyhala inicializacia kniznice WinSock! Chyba %d\n", initError);
		printf("Pokracujte stlacenim klavesu ENTER\n");
		WSACleanup();
		getchar();
		return 1;
	}

	udpsocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udpsocket == INVALID_SOCKET) {
		printf("Zlyhalo vytvorenie socketu! Chyba %d\n", WSAGetLastError());
		printf("Pokracujte stlacenim klavesu ENTER\n");
		WSACleanup();
		getchar();
		return 1;
	}

	printf("Inicializacia prijimaca\n");
	memset((char *)& recv_addr, 0, sizeof(SOCKADDR_IN));
	recv_addr.sin_family = AF_INET;
	recv_addr.sin_port = htons(port);
	recv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(udpsocket, (SOCKADDR *)& recv_addr, sizeof(recv_addr)) != 0) {
		printf("Nabindovanie socketu sa nepodarilo! Chyba %d\n", WSAGetLastError());
		printf("Pokracujte stlacenim klavesu ENTER\n");
		closesocket(udpsocket);
		WSACleanup();
		getchar();
		return 1;
	}

	// Prijaty paket a jeho dlzka
	packet *prijaty_paket = new packet;
	
	// Buffer pre prichadzajuce data
	char *fragment_buffer = (char *) malloc (maxSize);

	// Hlavicka je na zaciatku prijatych dat
	header *fragment_header = (header *) fragment_buffer;

	// Prichadzajuca adresa
	int address_size = sizeof(SOCKADDR_IN);
	SOCKADDR_IN address;

	// Vysielany paket s potvrdenim
	packet *vysielany_paket = new packet;

	// Vysielana hlavicka s potvrdenim
	header *vysielana_hlavicka = new header;

	while (1) {
		printf("Cakam na data\n");

		// Cakanie na data
		int recv_size = recvfrom(udpsocket, fragment_buffer, maxSize, 0, (SOCKADDR *)& address, &address_size);

		if (recv_size == SOCKET_ERROR) {
			printf("Nepodarilo sa prijat data. Chyba %d\n", WSAGetLastError());
			continue;
		}

		prijaty_paket->data = (unsigned char*) fragment_buffer;
		prijaty_paket->dlzka = recv_size;
		prijaty_paket = deenkapsulacia(fragment_header, prijaty_paket);

		char pStringBuf[16];
		printf("Bolo prijatych %d bajtov dat od %s na porte %d\n", recv_size, InetNtop(AF_INET, &address.sin_addr, pStringBuf, 16), ntohs(address.sin_port));
		printf("Sprava dlzky %lu: %.*s\n", fragment_header->dlzka, fragment_header->dlzka, prijaty_paket->data);

		vysielany_paket->data = NULL;
		vysielany_paket->dlzka = 0;
		vysielana_hlavicka->poradie = fragment_header->poradie;
		vysielana_hlavicka->total = fragment_header->total;
		vysielana_hlavicka->dlzka = 0;
		vysielana_hlavicka->flags = 0;
		vysielany_paket = enkapsulacia(*vysielana_hlavicka, vysielany_paket);

		sendto(udpsocket, (const char *) vysielany_paket->data, vysielany_paket->dlzka, 0, (SOCKADDR *)& address, address_size);
	}

	closesocket(udpsocket);
	WSACleanup();
	return 0;
}

// Spusti vysielac
int vysielac() {
	int velkostFragmentu, initError;
	//char volba;

	WSADATA wsaData;
	SOCKET udpsocket = INVALID_SOCKET;
	SOCKADDR_IN send_addr;
	unsigned int addr_size = sizeof(SOCKADDR_IN);
	DWORD timeout = socket_timeout_sec * 1000;

	printf("Inicializacia vysielaca\n");
	initError = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (initError != NO_ERROR) {
		printf("Zlyhala inicializacia kniznice WinSock! Chyba %d\n", initError);
		printf("Pokracujte stlacenim klavesu ENTER\n");
		WSACleanup();
		getchar();
		return 1;
	}

	udpsocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udpsocket == INVALID_SOCKET) {
		printf("Zlyhalo vytvorenie socketu! Chyba %d\n", WSAGetLastError());
		printf("Pokracujte stlacenim klavesu ENTER\n");
		WSACleanup();
		getchar();
		return 1;
	}

	if (setsockopt(udpsocket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) == SOCKET_ERROR) {
		printf("Zlyhalo nastavenie timeout-u socketu! Chyba %d\n", WSAGetLastError());
		printf("Pokracujte stlacenim klavesu ENTER\n");
		WSACleanup();
		getchar();
		return 1;
	}

	printf("Zadajte velkost fragmentu:\n");
	scanf("%d", &velkostFragmentu);
	getchar();	// preskocenie noveho riadku

	memset((char *)& send_addr, 0, addr_size);
	send_addr.sin_family = AF_INET;
	send_addr.sin_port = htons(port);

	if (InetPton(AF_INET, "127.0.0.1", &send_addr.sin_addr) != 1) {
		printf("InetPton zlyhal! Chyba %d\n", WSAGetLastError());
		printf("Pokracujte stlacenim klavesu ENTER\n");
		WSACleanup();
		getchar();
		return 1;
	}

	// Vysielane udaje a ich velkost
	packet *vysielany_paket = new packet;

	// Buffer pre vysielane data
	char *fragment_buffer = (char *) malloc (maxSize);
	
	// Hlavicka je na zaciatku vysielanych dat
	header *fragment_header = (header *) fragment_buffer;

	// Za hlavickou nasleduju data
	//char *fragment_data = fragment_buffer + headerSize;

	// Prijaty paket a jeho dlzka
	packet *prijaty_paket = new packet;
	prijaty_paket->data = (unsigned char *) malloc (maxSize);
	prijaty_paket->dlzka = 0;

	// Prijata hlavicka
	header *prijata_hlavicka = new header;

	// Prichadzajuca adresa
	SOCKADDR_IN recv_addr;
	memset((char *)& recv_addr, 0, sizeof(SOCKADDR_IN));
	int recv_addr_size = sizeof(recv_addr);

	// Zadavany text
	std::string text;

	// Buffer na ulozenie "string" IP adresy ciela vysielania
	char sStringBuf[16];

	// Buffer na ulozenie "string" IP adresy zdroja odpovede
	char rStringBuf[16];

	while (1) {
		printf("\nZadaj text\n");
		std::getline(std::cin, text);
		fragment_header->poradie = 1;
		fragment_header->total = 1;
		fragment_header->flags = 0;
		vysielany_paket->dlzka = text.size();
		vysielany_paket->data = (unsigned char *) text.c_str();
		vysielany_paket = enkapsulacia(*fragment_header, vysielany_paket);

		for (int i = 1; i <= 5; i++) {
			printf("Pokus o odoslanie %d/5\n", i);
			sendto(udpsocket, (const char *)vysielany_paket->data, vysielany_paket->dlzka, 0, (SOCKADDR *)& send_addr, addr_size);

			printf("Cakam na potvrdzujuci paket\n");
			int recv_size = recvfrom(udpsocket, (char *) prijaty_paket->data, maxSize, 0, (SOCKADDR *)& recv_addr, (int *) &recv_addr_size);

			if (recv_size == SOCKET_ERROR) {
				printf("Nepodarilo sa prijat data. Chyba %d\n", WSAGetLastError());

				if (i == 5) {
					printf("Prijimac neodpoveda, ukoncujem vysielac\n");
					closesocket(udpsocket);
					WSACleanup();
					return 1;
				}

				continue;
			}

			prijaty_paket->dlzka = recv_size;
			prijaty_paket = deenkapsulacia(prijata_hlavicka, prijaty_paket);

			if (strcmp(InetNtop(AF_INET, &recv_addr.sin_addr, rStringBuf, 16), InetNtop(AF_INET, &send_addr.sin_addr, sStringBuf, 16)) == 0) {
				if (debug) {
					printf("IP adresy ciela a prijateho ACK sa zhoduju\n");
				}
			}
			// TODO overenie ci ide o ACK
			break;
		}
	}

	/*printf("Chcete odoslat text alebo subor? [T/S]\n");
	printf("Vysielac ukoncite stlacenim klavesu X\n");

	while (volba = getchar()) {
		getchar();	// Preskocenie znaku '\n'

		switch (volba) {
			case 'T':
			case 't':
				break;
			case 's':
			case 'S':
			case 'f':
			case 'F':
				printf("Chyba: Tato funkcionalita nie je implementovana, skuste nejaku inu\n");
				break;
			case 'x':
			case 'X':
				printf("Ukoncujem vysielac\n");
				closesocket(udpsocket);
				WSACleanup();
				return 0;
			default:
				printf("Znak \"%c\" nie je platnou volbou!\n", volba);
				break;
		}

		printf("Chcete odoslat text alebo subor? [T/S]\n");
		printf("Vysielac ukoncite stlacenim klavesu X\n");
	}*/

	closesocket(udpsocket);
	WSACleanup();
	return 0;
}

int main() {
	char volba;

	printf("Budem vysielac alebo prijimac? [V/P]\n");
	printf("Program ukoncite stlacenim klavesu X\n");

	while (volba = getchar()) {
		getchar();	// Preskocenie znaku '\n'

		switch (volba) {
			case 'v':
			case 'V':
				vysielac();
				break;
			case 'p':
			case 'P':
				prijimac();
				break;
			case 'x':
			case 'X':
				return 0;
			default:
				printf("Znak \"%c\" nie je platnou volbou!\n", volba);
				break;
		}

		printf("\nBudem vysielac alebo prijimac? [V/P]\n");
		printf("Program ukoncite stlacenim klavesu X\n");
	}

	return 0;
}
