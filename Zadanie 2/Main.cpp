// Zadanie 2 - Pocitacove a komunikacne systemy
// Stanislav Jakubek, utorok 18:00, PU1

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <string>
#include <iostream>
#include <vector>

#pragma comment(lib, "Ws2_32.lib")

// Hlavicka vlastneho protokolu
struct header {
	unsigned long poradie;
	unsigned long total;
	unsigned long dlzka;
	unsigned long checksum;
	unsigned long flags;

#define DATA 0
#define ACK 0xfff00fff
};

// Struktura na uchovavanie dat
struct packet {
	unsigned long dlzka;
	unsigned char *data;
};

// Struktura na uchovavanie fragmentu
struct fragment {
	unsigned char *data;
	unsigned short dlzka;
	unsigned long id;
};

#define debug 0
#define vnesenie_chyby 0

#define port 8086
#define maxSize 65507 // 65535 (max_udp_length) - 20 (ip_header_size) - 8 (udp_header_size)
#define polynom 0xedb88320
#define socket_timeout_sec 2
#define headerSize sizeof(header)

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

// Rozdeli data na jednotlive fragmenty
std::vector<fragment> fragmentacia(packet *data, unsigned long maxVelkostFragmentu) {
	std::vector<fragment> result;
	unsigned long dlzkaFragmentu, i = 1, offset = 0;

	while (offset < data->dlzka) {
		if (data->dlzka - offset < maxVelkostFragmentu) {
			dlzkaFragmentu = data->dlzka - offset;
		}
		else {
			dlzkaFragmentu = maxVelkostFragmentu;
		}

		fragment *akt = new fragment;
		akt->data = data->data + offset;
		akt->dlzka = dlzkaFragmentu;
		akt->id = i++;

		result.push_back(*akt);

		offset += dlzkaFragmentu;
	}

	if (debug) {
		printf("Fragmentacia spravy dlzky %d\n", data->dlzka);
		printf("Maximalna velkost fragmentu: %d\n", maxVelkostFragmentu);
		printf("Sprava: %s\n", data->data);

		for (i = 0; i < result.size(); i++) {
			printf("id: %d\n", result[i].id);
			printf("dlzka: %d\n", result[i].dlzka);
			printf("data: %.*s\n", result[i].dlzka, result[i].data);
		}
	}

	return result;
}

// Spoji jednotlive fragmenty dohromady
packet *defragmentacia(std::vector<fragment> fragmenty) {
	packet *result = new packet;
	unsigned long i, j, offset = 0, dlzkaDat = 0;

	for (i = 0; i < fragmenty.size(); i++) {
		dlzkaDat += fragmenty[i].dlzka;
	}

	if (debug) {
		printf("Defragmentacia spravy dlzky %d\n", dlzkaDat);
		printf("Pocet fragmentov: %d\n", fragmenty.size());
	}

	result->dlzka = dlzkaDat;
	result->data = (unsigned char *) malloc (dlzkaDat);

	for (i = 0; i < fragmenty.size(); i++) {
		if (debug) {
			printf("Fragment %d\n", i+1);
			printf("Sprava: %.*s\n", fragmenty[i].dlzka, fragmenty[i].data);
		}

		for (j = 0; j < fragmenty[i].dlzka; j++) {
			*(result->data + offset + j) = *(fragmenty[i].data + j);
		}
		offset += fragmenty[i].dlzka;
	}

	if (debug) {
		printf("Defragmentovana sprava: %.*s\n", result->dlzka, result->data);
	}

	return result;
}

// Obali data hlavickou
packet *enkapsulacia(header hlavicka, packet *data) {
	packet *final = new packet;
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
	packet *final = new packet;
	
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
	int i, initError;

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
	header *fragment_header = new header;

	// Prichadzajuca adresa
	SOCKADDR_IN address;

	// Velkost prichadzajucej adresy
	int address_size = sizeof(SOCKADDR_IN);

	// Vysielany paket s potvrdenim
	packet *vysielany_paket = new packet;

	// Vysielana hlavicka s potvrdenim
	header *vysielana_hlavicka = new header;

	// Pomocny buffer pre InetNtop
	char pStringBuf[16];

	// Pole fragmentov spravy
	std::vector<fragment> fragmenty;

	// Sucasny prijaty fragment
	fragment *tmp;

	// Packet na uchovanie celej spravy
	packet *sprava;

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

		printf("Bolo prijatych %d bajtov dat od %s na porte %d\n", recv_size, InetNtop(AF_INET, &address.sin_addr, pStringBuf, 16), ntohs(address.sin_port));

		// Ak nesedi checksum tak nepotvrdi prijatie paketu
		if (prijaty_paket == NULL) {
			printf("Zly checksum, zahadzujem paket\n");
			prijaty_paket = new packet;
			continue;
		}

		printf("Sprava %d/%d dlzky %lu: %.*s\n", fragment_header->poradie, fragment_header->total, fragment_header->dlzka, fragment_header->dlzka, prijaty_paket->data);

		// Ak dany fragment este nebol prijaty
		if (fragmenty.size() == (fragment_header->poradie - 1)) {
			tmp = new fragment;
			tmp->data = prijaty_paket->data;
			tmp->dlzka = prijaty_paket->dlzka;
			tmp->id = fragment_header->poradie;
			fragmenty.push_back(*tmp);
		}

		vysielany_paket->data = NULL;
		vysielany_paket->dlzka = 0;
		vysielana_hlavicka->poradie = fragment_header->poradie;
		vysielana_hlavicka->total = fragment_header->total;
		vysielana_hlavicka->dlzka = 0;
		vysielana_hlavicka->flags = ACK;
		vysielany_paket = enkapsulacia(*vysielana_hlavicka, vysielany_paket);

		sendto(udpsocket, (const char *) vysielany_paket->data, vysielany_paket->dlzka, 0, (SOCKADDR *)& address, address_size);

		if (fragmenty.size() == fragment_header->total) {
			sprava = defragmentacia(fragmenty);
			printf("Defragmentovana sprava dlzky %d: %.*s\n", sprava->dlzka, sprava->dlzka, sprava->data);
			fragmenty.clear();
		}
	}

	closesocket(udpsocket);
	WSACleanup();
	return 0;
}

// Spusti vysielac
int vysielac() {
	int i, j, maxVelkostFragmentu, initError;

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

	printf("Zadajte maximalnu velkost fragmentu:\n");
	scanf("%d", &maxVelkostFragmentu);
	getchar();	// preskocenie noveho riadku

	if (maxVelkostFragmentu < 1) {
		printf("Neplatna velkost fragmentu!\n");
		printf("Pokracujte stlacenim klavesu ENTER\n");
		WSACleanup();
		getchar();
		return 1;
	}

	// Zadavana IP adresa prijimaca
	std::string IPprijimaca;
	printf("Zadajte IP adresu prijimaca (format A.B.C.D):\n");
	std::getline(std::cin, IPprijimaca);

	memset((char *)& send_addr, 0, addr_size);
	send_addr.sin_family = AF_INET;
	send_addr.sin_port = htons(port);

	if (InetPton(AF_INET, IPprijimaca.c_str(), &send_addr.sin_addr) != 1) {
		printf("InetPton zlyhal! Chyba %d\n", WSAGetLastError());
		printf("Pokracujte stlacenim klavesu ENTER\n");
		WSACleanup();
		getchar();
		return 1;
	}

	// Vysielane udaje a ich velkost
	packet *vysielany_paket = new packet;
	
	// Hlavicka vysielanych dat
	header *fragment_header = new header;

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

	// Pole fragmentov spravy
	std::vector<fragment> fragmenty;

	// Packet na uchovanie celej spravy
	packet *sprava = new packet;

	// Pocet fragmentov
	unsigned int pocetFragmentov;

	// Pomocna premenna pre vnesenie chyby
	unsigned char tmp;

	while (1) {
		printf("\nZadaj text\n");
		std::getline(std::cin, text);

		sprava->dlzka = text.size();
		sprava->data = (unsigned char *) text.c_str();

		fragmenty = fragmentacia(sprava, maxVelkostFragmentu);

		if ((sprava->dlzka % maxVelkostFragmentu) == 0) {
			pocetFragmentov = sprava->dlzka / maxVelkostFragmentu;
		}
		else if (sprava->dlzka < maxVelkostFragmentu) {
			pocetFragmentov = 1;
		}
		else {
			pocetFragmentov = sprava->dlzka / maxVelkostFragmentu + 1;
		}

		for (i = 0; i < pocetFragmentov; i++) {
			fragment_header->poradie = i + 1;
			fragment_header->total = pocetFragmentov;
			fragment_header->flags = DATA;
			vysielany_paket->dlzka = fragmenty[i].dlzka;
			vysielany_paket->data = fragmenty[i].data;
			vysielany_paket = enkapsulacia(*fragment_header, vysielany_paket);

			if (vnesenie_chyby) {
				tmp = (vysielany_paket->data)[2];
			}

			for (j = 1; j <= 5; j++) {
				if (vnesenie_chyby) {
					if ((i == 0) && (j == 1)) {
						(vysielany_paket->data)[2] = ~tmp;
					}
					else {
						(vysielany_paket->data)[2] = tmp;
					}
				}

				printf("Pokus %d/5 o odoslanie fragmentu %d/%d\n", j, i+1, pocetFragmentov);
				sendto(udpsocket, (const char *)vysielany_paket->data, vysielany_paket->dlzka, 0, (SOCKADDR *)& send_addr, addr_size);

				printf("Cakam na potvrdzovaci paket\n");
				int recv_size = recvfrom(udpsocket, (char *)prijaty_paket->data, maxSize, 0, (SOCKADDR *)& recv_addr, (int *)&recv_addr_size);

				if (recv_size == SOCKET_ERROR) {
					printf("Nepodarilo sa prijat data. Chyba %d\n", WSAGetLastError());

					if (j == 5) {
						printf("Prijimac neodpoveda, ukoncujem vysielac\n");
						closesocket(udpsocket);
						WSACleanup();
						return 1;
					}

					continue;
				}

				prijaty_paket->dlzka = recv_size;
				prijaty_paket = deenkapsulacia(prijata_hlavicka, prijaty_paket);

				// Ak nesedi checksum prijateho paketu
				if (prijaty_paket == NULL) { continue; }

				if ((strcmp(InetNtop(AF_INET, &recv_addr.sin_addr, rStringBuf, 16), InetNtop(AF_INET, &send_addr.sin_addr, sStringBuf, 16)) == 0) &&
					(prijata_hlavicka->flags == ACK) && (prijata_hlavicka->poradie == fragment_header->poradie) && (prijata_hlavicka->total == fragment_header->total)){
					printf("Potvrdzovaci paket uspesne prijaty!\n");
				}
				else {
					printf("Nebol prijaty korektny potvrdzovaci paket\n");

					if (j == 5) {
						printf("Prijimac neodpoveda korektne, ukoncujem vysielac\n");
						closesocket(udpsocket);
						WSACleanup();
						return 1;
					}

					continue;
				}

				break;
			}
		}
	}

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