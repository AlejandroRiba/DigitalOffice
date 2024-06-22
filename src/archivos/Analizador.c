#include <stdio.h>
#include <stdlib.h>

void LLC(unsigned char t[]);
void analizaTrama(unsigned char t[], unsigned char i);
void IP(unsigned char t[]);
void ARP(unsigned char t[]);
unsigned short int checksum(unsigned char t[], unsigned char tam);
void ICMP(unsigned char t[], unsigned char IHL);
void TCP(unsigned char t[], unsigned char IHL);
void UDP(unsigned char t[], unsigned char IHL);

int main()
{
	unsigned char t[][200] =
		{

			{// T1
			 0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x08, 0x00, 0x46, 0x00,
			 0x80, 0x42, 0x04, 0x55, 0x34, 0x11, 0x80, 0x11, 0x6b, 0xf0, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc,
			 0x67, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x04, 0x0c, 0x00, 0x35, 0x00, 0x2e, 0x85, 0x7c, 0xe2, 0x1a,
			 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x03, 0x69,
			 0x73, 0x63, 0x05, 0x65, 0x73, 0x63, 0x6f, 0x6d, 0x03, 0x69, 0x70, 0x6e, 0x02, 0x6d, 0x78, 0x00,
			 0x00, 0x1c, 0x00, 0x01},

			{// T2
			 0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x08, 0x00, 0x45, 0x00,
			 0x00, 0x30, 0x05, 0xc4, 0x40, 0x00, 0x80, 0x06, 0x71, 0xb0, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8,
			 0x01, 0x02, 0x00, 0x15, 0x04, 0x03, 0x21, 0x5d, 0x3a, 0x44, 0x00, 0x3b, 0xcf, 0x45, 0x70, 0x12,
			 0x44, 0x70, 0x8c, 0x11, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02},

			{// T3
			 0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x08, 0x00, 0x45, 0x00,
			 0x00, 0x6f, 0x90, 0x30, 0x40, 0x00, 0xfb, 0x11, 0x24, 0xe7, 0x94, 0xcc, 0x67, 0x02, 0x94, 0xcc,
			 0x39, 0xcb, 0x00, 0x35, 0x04, 0x0c, 0x00, 0x5b, 0xe8, 0x60, 0xe2, 0x1a, 0x85, 0x80, 0x00, 0x01,
			 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x03, 0x69, 0x73, 0x63, 0x05, 0x65,
			 0x73, 0x63, 0x6f, 0x6d, 0x03, 0x69, 0x70, 0x6e, 0x02, 0x6d, 0x78, 0x00, 0x00, 0x1c, 0x00, 0x01,
			 0xc0, 0x14, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x21, 0x04, 0x64, 0x6e, 0x73,
			 0x31, 0xc0, 0x1a, 0x03, 0x74, 0x69, 0x63, 0xc0, 0x1a, 0x77, 0xec, 0xdf, 0x29, 0x00, 0x00, 0x2a,
			 0x30, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x12, 0x75, 0x00, 0x00, 0x00, 0x2a, 0x30},

			{// T4
			 0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x08, 0x00, 0x45, 0x00,
			 0x00, 0x30, 0x2c, 0x00, 0x40, 0x00, 0x80, 0x06, 0x4b, 0x74, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8,
			 0x01, 0x01, 0x04, 0x03, 0x00, 0x15, 0x00, 0x3b, 0xcf, 0x44, 0x00, 0x00, 0x00, 0x00, 0x70, 0x20,
			 0x20, 0x00, 0x0c, 0x34, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02},

			{// T5
			 0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x08, 0x00, 0x45, 0x00,
			 0x00, 0x30, 0x2c, 0x00, 0x40, 0x00, 0x80, 0x06, 0x4b, 0x74, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8,
			 0x01, 0x01, 0x04, 0x03, 0x00, 0x15, 0x00, 0x3b, 0xcf, 0x44, 0x00, 0x00, 0x00, 0x00, 0x50, 0x15,
			 0x20, 0x00, 0x0c, 0x34, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02},

			{// T6
			 0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x08, 0x00, 0x45, 0x00,
			 0x00, 0x30, 0x2c, 0x00, 0x40, 0x00, 0x80, 0x06, 0x4b, 0x74, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8,
			 0x01, 0x01, 0x04, 0x03, 0x00, 0x15, 0x00, 0x3b, 0xcf, 0x44, 0x00, 0x00, 0x00, 0x00, 0x50, 0x25,
			 0x20, 0x00, 0x0c, 0x34, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02}

		};
	unsigned char i;

	for (i = 0; i < 6; i++)
	{
		analizaTrama(t[i], i);
	}

	return 0;
}

void analizaTrama(unsigned char t[], unsigned char i)
{
	printf("-----------------------------------\n");
	printf("Trama %d \n", i + 1);
	printf("\n*** Cabecera Ethernet ***\n");
	printf("MAC destino: %02X:%02X:%02X:%02X:%02X:%02X\n", t[0], t[1], t[2], t[3], t[4], t[5]);
	printf("MAC origen: %02X:%02X:%02X:%02X:%02X:%02X\n", t[6], t[7], t[8], t[9], t[10], t[11]);

	unsigned short int ToT = t[12] << 8 | t[13];

	if (ToT < 1500)
	{
		printf("Tamano de la cabecera LLC es de %d bytes\n\n", ToT);
		LLC(t);
	}
	else if (ToT == 2048)
	{
		printf("TIPO IP\n");
		IP(t);
	}
	else if (ToT == 2054)
	{
		printf("TIPO ARP\n");
		ARP(t);
	}
	else
	{
		printf("OTRO TIPO (0x%04X)\n", ToT);
	}

	printf("-----------------------------------\n");
}

unsigned short int checksum(unsigned char t[], unsigned char tam)
{
	unsigned char i;
	unsigned int suma = 0;

	for (i = 0; i < tam; i += 2)
	{
		suma += t[i] << 8 | t[i + 1];
	}

	return ~((suma & 0xffff) + (suma >> 16));
}

void ARP(unsigned char T[])
{
	printf("\n*** Cabecera ARP ***\n");
	if ((T[14] << 8) | T[15] == 1)
		printf("Dir HW tipo Ethernet\n");
	else if ((T[14] << 8) | T[15] == 6)
		printf("Dir HW tipo IEEE 802 LAN\n");
	else
		printf("Dir HW tipo otro\n");

	if ((T[16] << 8) | T[17] == 2048)
		printf("Dir protocolo tipo IPV4\n");
	else
		printf("Dir protocolo tipo otro\n");

	printf("Long dir HW = %d bytes\n", T[18]);

	printf("Long dir protocolo = %d bytes\n", T[19]);

	if ((T[20] << 8) | T[21] == 1)
		printf("Solicitud\n");
	else if ((T[20] << 8) | T[21] == 2)
		printf("Respuesta\n");

	printf("MAC orignen: %02X:%02X:%02X:%02X:%02X:%02X\n", T[22], T[23], T[24], T[25], T[26], T[27]);

	printf("IP orignen: %d.%d.%d.%d\n", T[28], T[29], T[30], T[31]);

	printf("MAC destino: %02X:%02X:%02X:%02X:%02X:%02X\n", T[32], T[33], T[34], T[35], T[36], T[37]);

	printf("IP destino: %d.%d.%d.%d\n", T[38], T[39], T[40], T[41]);
}

void LLC(unsigned char t[])
{
	unsigned char uc[][6] = {"UI", "SIM", "-", "SARM", "UP", "-", "-", "SABM", "DISC", "-", "-", "SARME", "-", "-", "-", "SABME", "SNRM", "-", "-", "RSET", "-", "-", "-", "XID", "-", "-", "-", "SNRME"};
	unsigned char ur[][6] = {"UI", "RIM", "-", "DM", "-", "-", "-", "-", "RD", "-", "-", "-", "UA", "-", "-", "-", "-", "FRMR", "-", "-", "-", "-", "-", "XID"};
	unsigned char ss[][5] = {"RR", "RNR", "REJ", "SREJ"};

	printf("*** Cabecera LLC ***\n");
	switch (t[16] & 3)
	{
	case 1: // Trama S
		printf("T-S %s, N(r)=%d", ss[(t[16] >> 2) & 3], t[17] >> 1);
		if (t[17] & 1)
		{
			if (t[15] & 1)
			{
				printf(", F\n");
			}
			else
			{
				printf(", P\n");
			}
		}
		else
		{
			printf("\n");
		}
		break;
	case 3: // Trama U
		printf("T-U ");

		if (t[16] & 16)
		{
			if (t[15] & 1)
			{
				printf("%s, F\n", ur[(t[16] >> 2) & 3 | (t[16] >> 3) & 28]);
			}
			else
			{
				printf("%s, P\n", uc[(t[16] >> 2) & 3 | (t[16] >> 3) & 28]);
			}
		}
		break;
	default: // Trama I
		printf("T-I, N(s)=%d, N(r)=%d", t[16] >> 1, t[17] >> 1);
		if (t[17] & 1)
		{
			if (t[15] & 1)
			{
				printf(", F\n");
			}
			else
			{
				printf(", P\n");
			}
		}
		else
		{
			printf("\n");
		}
		break;
	}
}

void IP(unsigned char t[])
{
	unsigned char IHL = (t[14] & 15) << 2;

	printf("\n*** Cabecera IP ***\n");
	printf("Version: IPv%d\n", t[14] >> 4);
	printf("IHL = %d Bytes\n", (t[14] & 15) << 2);

	if (t[15] & 16)
		printf("Retardo minimo\n");
	if (t[15] & 8)
		printf("Maximiza todo\n");
	if (t[15] & 4)
		printf("Maximizar fiabilidad\n");
	if (t[15] & 2)
		printf("Costo minimo\n");

	printf("Total Length = %d Bytes\n", (t[16] << 8) | t[17]);
	printf("ID: %d\n", (t[18] << 8) | t[19]);

	if (t[20] & 64)
		printf("No fragmentos\n");
	if (t[20] & 32)
		printf("Mas fragmentos\n");

	printf("Offset de Fragmentos = %d Bytes\n", ((t[20] << 8) | t[21]) << 3);
	printf("TTL = %d saltos\n", t[22]);

	printf("Header checksum = %d\n", (t[24] << 8) | t[25]);

	printf("Direccion origen: %d.%d.%d.%d\n", t[26], t[27], t[28], t[29]);
	printf("Direccion destino: %d.%d.%d.%d\n", t[30], t[31], t[32], t[33]);

	if (t[23] == 1)
	{
		printf("ICMP\n");
		ICMP(t, IHL);
	}
	else if (t[23] == 6)
	{
		printf("TCP\n");
		TCP(t, IHL);
	}
	else if (t[23] == 17)
	{
		printf("UDP\n");
		UDP(t, IHL);
	}
	else
		printf("OTRO %02X\n", t[23]);
}

void ICMP(unsigned char t[], unsigned char IHL)
{
	unsigned char i;
	printf("\n*** Cabecera ICMP ***\n");

	if (t[14 + IHL] == 8 && t[15 + IHL] == 0)
	{
		printf("Solicitud ECO\n");
		printf("Checksum = 0x%02X%02X\n", t[16 + IHL], t[17 + IHL]);
		printf("Identificador = %d\n", (t[18 + IHL] << 8) | t[19 + IHL]);
		printf("Numero de secuencia = %d\n", (t[20 + IHL] << 8) | t[21 + IHL]);
		printf("Datos opc: ");
		for (i = 0; i < 32; i++)
		{
			printf("%c", t[22 + IHL + i]);
		}
		printf("\n");
	}
	else if (t[14 + IHL] == 0 && t[14 + IHL] == 0)
	{
		printf("Respuesta ECO\n");
		printf("Checksum = 0x%02X%02X\n", t[16 + IHL], t[17 + IHL]);
		printf("Identificador = %d\n", (t[18 + IHL] << 8) | t[19 + IHL]);
		printf("Numero de secuencia = %d\n", (t[20 + IHL] << 8) | t[21 + IHL]);
		printf("Datos opc: ");
		for (i = 0; i < 32; i++)
		{
			printf("%c", t[22 + IHL + i]);
		}
		printf("\n");
	}
	else
	{
		printf("Tipo = %d\n", t[14 + IHL]);
		printf("Codigo = %d\n", t[15 + IHL]);
		printf("Checksum = 0x%02X%02X\n", t[16 + IHL], t[17 + IHL]);
	}
}

void TCP(unsigned char t[], unsigned char IHL)
{
	unsigned char pseudo[12], i;
	unsigned char offset = (t[26 + IHL] >> 2) & 60;
	printf("\n*** Cabecera TCP ***\n");

	for (i = 0; i < 4; i++)
	{
		pseudo[i] = t[26 + i];
		pseudo[i + 4] = t[30 + i];
	

	pseudo[8] = 0;
	pseudo[9] = 0x06;
	pseudo[10] = 0;
	pseudo[11] = (t[26 + IHL] >> 2);
	}
	unsigned char cabChksum[offset + 12];

	for (i = 0; i < 12 + offset; i++)
	{
		if (i < 12)
		{
			cabChksum[i] = pseudo[i];
		}
		else
		{
			cabChksum[i] = t[2 + IHL + i];
		}

		printf("%02X ", cabChksum[i]);
	}
	printf("\n");

	printf("Checksum = 0x%02X%02X\n", t[30 + IHL], t[31 + IHL]);

	if (checksum(cabChksum, offset + 12))
	{
		printf("Trama incorrecta\n");
	}
	else
		printf("Trama correcta\n");

	// Bandera de urgencia
	if (t[27 + IHL] & 0x20)
	{
		unsigned int numsec = t[18 + IHL];
		for (i = 1; i < 4; i++)
		{
			numsec = (numsec << 8) | t[18 + IHL + i];
		}

		printf("Bandera de Urgencia! 0x%02X\nNumero de secuencia = %d\n",t[27 + IHL], numsec);
	}

	// TCP tiene opciones
	unsigned char header_length = (t[26 + IHL] >> 4) << 2;
	if (header_length > 20)
	{
		printf("Puerto Origen = 0x%04x\n", t[14 + IHL] << 8 | t[15 + IHL]);
		printf("Puerto Destino = 0x%04x\n", t[16 + IHL] << 8 | t[17 + IHL]);
	}
}

void UDP(unsigned char t[], unsigned char IHL)
{
	printf("\n*** Cabecera UDP ***\n");
	printf("Puerto Origen = 0x%04x\n", (t[14 + IHL] << 8 | t[15 + IHL]));
	printf("Puerto Destino = 0x%04x\n", (t[16 + IHL] << 8 | t[17 + IHL]));
	printf("Longitud = %d\n", (t[18 + IHL] << 8 | t[19 + IHL]));
	printf("Checksum = 0x%04x\n", (t[20 + IHL] << 8 | t[21 + IHL]));
}
