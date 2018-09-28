// vblade O/S interface functions re-written for winpcap


#include "pcap.h"
#include "pcap-int.h"
#include "packet32.h"
#include "ntddndis.h"
#include <unistd.h>
#include <sys/ioctl.h>
#include <cygwin/fs.h>

#include <assert.h>

#include "dat.h"
#include "fns.h"


// Several functions are copied from winpcap example source; here
// is the copyright:
/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies
 * nor the names of its contributors may be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

// - modified from winpcap example program GetMacAddress.c


static uchar g_mac_addr[6];
static int g_mtu = 1500;
static pcap_t *g_fp;

static int UpdateMacAddress(LPADAPTER adapter)
{
    PPACKET_OID_DATA  OidData;
    BOOLEAN     Status;

    // Allocate a buffer to get the MAC adress
    OidData = malloc(6 + sizeof(PACKET_OID_DATA));
    if (OidData == NULL) {
        printf("error allocating memory!\n");
        return -1;
    }

    // Retrieve the adapter MAC querying the NIC driver
    OidData->Oid = OID_802_3_CURRENT_ADDRESS;
    OidData->Length = 6;
    ZeroMemory(OidData->Data, 6);

    Status = PacketRequest(adapter, FALSE, OidData);
    if (Status) {
        printf("The MAC address of the adapter is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
               (UCHAR)(OidData->Data)[0],
               (UCHAR)(OidData->Data)[1],
               (UCHAR)(OidData->Data)[2],
               (UCHAR)(OidData->Data)[3],
               (UCHAR)(OidData->Data)[4],
               (UCHAR)(OidData->Data)[5]);
        memcpy(g_mac_addr, OidData->Data, 6);
    } else {
        DWORD dwErrorCode = GetLastError();
        printf("Error retrieving the MAC address of the adapter! Error Code : %x\n", (int)dwErrorCode);
        free(OidData);
        return -1;
    }
    free(OidData);
    return (0);
}

static int UpdateMTU(LPADAPTER adapter)
{
    PPACKET_OID_DATA  OidData;
    BOOLEAN     Status;

    // Allocate a buffer
    OidData = malloc(4 + sizeof(PACKET_OID_DATA));
    if (OidData == NULL) {
        printf("error allocating memory!\n");
        return -1;
    }

    // query the NIC driver
    OidData->Oid = OID_GEN_MAXIMUM_FRAME_SIZE;
    OidData->Length = 4;
    ZeroMemory(OidData->Data, 4);

    Status = PacketRequest(adapter, FALSE, OidData);
    if (Status) {
        memcpy(&g_mtu, OidData->Data, 4);
        printf("The adapter MTU is %d\n", g_mtu);
    } else {
        DWORD dwErrorCode = GetLastError();
        printf("Error retrieving the adapter MT! Error Code : %x\n", (int)dwErrorCode);
        printf("Set MTU to default value: 1500\n");
        g_mtu = 1500;
    }
    free(OidData);
    return (0);
}

static int UpdateMacMtu(char *eth)
{
    LPADAPTER lpAdapter = 0;
    DWORD       dwErrorCode;

    lpAdapter =   PacketOpenAdapter(eth);
    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) {
        dwErrorCode = GetLastError();
        printf("Unable to open the adapter '%s', Error Code : %x\n", eth, (int)dwErrorCode);
        return -1;
    }
    UpdateMacAddress(lpAdapter);
    UpdateMTU(lpAdapter);
    PacketCloseAdapter(lpAdapter);
    return 0;
}

// open and initialize network adapter for AoE
int dial(char *eth, int bufcnt)
{
    // Since the winpcap network driver has such odd device names,
    // list them out so users can select the device.
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE + 1];
    char eth_name[256];
    pcap_t *fp;
    int inum;
    int i = 0;

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    if (strcmp(eth, "xxx")) {
        strcpy(eth_name, eth);
    } else {
        /* Print the list */
        for (d = alldevs; d; d = d->next) {
            printf("%d. %s", ++i, d->name);
            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }

        if (i == 0) {
            printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
            exit(1);
        }

        printf("Enter the interface number (1-%d): ", i);
        scanf("%d", &inum);

        if (inum < 1 || inum > i) {
            printf("\nInterface number out of range.\n");
            /* Free the device list */
            pcap_freealldevs(alldevs);
            exit(1);
        }

        /* Jump to the selected adapter */
        for (d = alldevs, i = 0; i < inum - 1 ; d = d->next, i++);
        strcpy(eth_name, d->name);
        /* Free the device list */
        pcap_freealldevs(alldevs);
    }

    //--------------------------
    UpdateMacMtu(eth_name);

    //do the AoE setup

    /* Open the adapter */
    if ((fp = pcap_open(eth_name,      // name of the device
                        65536,         // capture entire packet
                        PCAP_OPENFLAG_MAX_RESPONSIVENESS, // turn off caching
                        0,             // read timeout;  0 = no timeout
                        NULL,          // pcap_rmtauth*
                        errbuf         // error buffer
                       )) == NULL) {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", eth_name);
        exit(1);
    }
    g_fp = fp;

    /* Set the kernel capture buffer size*/
    if (pcap_setbuff(fp, bufcnt * g_mtu) != 0) {
        printf("Error setting the kernel buffer size(%s)\n", pcap_geterr(fp));
        pcap_close(fp);
        exit(1);
    }

    //create the filter
    void  *bpf_program = create_bpf_program(shelf, slot);

    //set the filter
    if (pcap_setfilter(fp, bpf_program) < 0) {
        fprintf(stderr, "\nError setting the filter\n");
        // vblade will work without the filter, so don't return an error
    }
    free_bpf_program(bpf_program);

    return (int)1;
}

// get ethernet hardware address
int getea(int s, char *name, uchar *ea)
{
    memcpy(ea, g_mac_addr, sizeof(g_mac_addr));
    return 0;
}

int getmtu(int s, char *name)
{
    return g_mtu;
}

int getsec(int fd, uchar *place, vlong lba, int nsec)
{
    return pread(fd, place, nsec * 512, lba * 512);
}

int putsec(int fd, uchar *place, vlong lba, int nsec)
{
    return pwrite(fd, place, nsec * 512, lba * 512);
}

int getpkt(int s, uchar *buf, int sz)
{
    struct pcap_pkthdr *header;
    uchar *pcap_buf = NULL;
    int status = 0;

    if ((status = pcap_next_ex(g_fp, &header, (const uchar **)&pcap_buf)) >= 1) {
        // copy pcap buffer to vblade buffer
        memcpy(buf, pcap_buf, header->len);
    } else {
        // pcap_next_ex occasionally returns 0 meaning "timeout", but the driver is
        // supposed to be setup for no timeout. Skip the error message for this condition;
        // it does not seem to harm AoE operation.
        if (status != 0) {
            fprintf(stderr, "\nError receiving the packet: %s\n", pcap_geterr(g_fp));
            printf("pcap_next_ex failed: %d \n", status);
        }
        return status;
    }
    return header->len;
}

int putpkt(int s, uchar *buf, int sz)
{
    if (pcap_sendpacket(g_fp,  // Adapter
                        buf,                // buffer with the packet
                        sz                  // size
                       ) != 0) {
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(g_fp));
        return -1;
    }
    return 0;
}

vlong getsize(int fd)
{
    vlong size;
    struct stat s;
    int n;

    n = ioctl(fd, BLKGETSIZE64, &size);
    if (n == -1) {  // must not be a block special
        n = fstat(fd, &s);
        if (n == -1) {
            perror("getsize");
            exit(1);
        }
        size = s.st_size;
    }
    return size;
}
