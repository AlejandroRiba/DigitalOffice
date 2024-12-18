#include <stdio.h>
unsigned short int checksum(unsigned char *, int, int);

void main(){
  //Declaración de variables
  unsigned char t[3][125]={{
  0xc0, 0xa8, 0x02, 0x3c, 0x4a, 0x7d, 0x5f, 0x68, 0x00, 0x06, 0x00,  0x1c, 0x10, 0x52, 0x00, 0x50, 
  0x03, 0xc7, 0x5a, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x70, 0x02, 0x40, 0x00, 0x67, 0x4b, 0x00, 0x00, 
  0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02},
  {0x00, 0x1f, 0x45, 0x9d, 0x1e, 0xa2, 0x00, 0x23, 0x8b, 0x46, 0xe9, 0xad, 0x08, 0x00, 0x45, 0x00, //TIP
  0x00, 0x3c, 0x04, 0x57, 0x00, 0x00, 0x80, 0x00, 0x98, 0x25, 0x94, 0xcc, 0x39, 0xcb, 0x94, 0xcc, 
  0x3a, 0xe1, 0x08, 0x00, 0x49, 0x5c, 0x03, 0x00, 0x01, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 
  0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 
  0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69},
  {0x02, 0xff, 0x53, 0xc3, 0xe9, 0xab, 0x00, 0xff, 0x66, 0x7f, 0xd4, 0x3c, 0x08, 0x00, 0x45, 0x00, //T11
  0x00, 0x30, 0x2c, 0x00, 0x40, 0x00, 0x80, 0x06, 0x4b, 0x74, 0xc0, 0xa8, 0x01, 0x02, 0xc0, 0xa8, 
  0x01, 0x01, 0x04, 0x03, 0x00, 0x15, 0x00, 0x3b, 0xcf, 0x44, 0x00, 0x00, 0x00, 0x00, 0x70, 0x20, 
  0x20, 0x00, 0x0c, 0x34, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x01, 0x04, 0x02}};
//unsigned short int tot = t[12] << 8 | t[13];
  unsigned char ihl = (t[0][14]&15)*4;
  /*if(tot<1500){
    printf("LLC");
  }elsif(tot==2048){
    printf("IP");
  }elsif(tot==2054){
    printf("ARP");
  }else{
    printf("Otro");
  }*/
  printf("checksum = 0x%04x", checksum(t[0],0,40));
}

//Función del checksum
unsigned short int checksum(unsigned char * t, int inicio, int fin) {
    int suma = 0;
    for (int i = inicio; i < fin; i += 2) {
      suma += t[i] << 8 | t[i + 1];
    }
    suma = (suma & 0xFFFF) + (suma >> 16);
    suma = ~(suma) & 0xFFFF; // Aseguramos que la suma es de 16 bits
    return suma;
}

void tramaARP(unsigned char T[]){
    printf("\n***CABECERA ARP***\n");

    //Tipo de dirección de Hardware

    if(T[15] == 1)
        printf("\nEthernet\n");
    else
        printf("\nIEEE 802 LAN\n");
    
 
    printf("\nTipo de direccion de Protocolo: %d\n", T[16]<<8 | T[17]);
    printf("\nTamaño de direccion de Hardware: %d\n", T[18]);
    printf("\nTamaño de direecion de Protocolo: %d\n", T[19]);
	
    //Operación
    if(T[21] == 1)
        printf("\nSolicitud\n");
    else    
        printf("\nRespuesta\n");
    
    printf("\nMAC Origen: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", T[22], T[23], T[24], T[25], T[26], T[27]);
    printf("\nIP Origen: %d.%d.%d.%d\n", T[28], T[29], T[30], T[31]);
    printf("\nMAC Destino: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",T[32], T[33], T[34], T[35], T[36], T[37]);
    printf("\nIP Destino: %d.%d.%d.%d\n", T[38], T[39], T[40], T[41]);
}
