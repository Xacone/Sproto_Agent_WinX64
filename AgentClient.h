#ifndef AGENTCLIENT_H
#define AGENTCLIENT_H

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "User32.lib")

#include "HeadersFiles.h"
#include <Windows.h>
#include "WinUser.h"


class CW_Agent_Thread : public QThread
{
    Q_OBJECT
private:
    pcap_if_t *dev;
    QObject *parent;
    pcap_t *handler;
    int pcap_next_packet;
    struct pcap_pkthdr *pckt_header;
    const u_char *pckt_data;
    bool _CAP_ALLOWED_ = true;
    QTcpSocket *sock;
    QByteArray _QBA_;
    bpf_u_int32 netmask;
    struct bpf_program bpf;

public:

    CW_Agent_Thread(pcap_t* handl, QObject *p, QTcpSocket *s, pcap_if_t* device) : dev(device), parent(p), handler(handl), sock(s) {}
    ~CW_Agent_Thread(){
        delete parent;
        delete handler;
        delete pckt_header;
    }

    void run() override {
        if(dev->addresses != NULL)
        {
            netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
        } else {
            netmask = 0xffffff;
        }

        if (pcap_compile(handler, &bpf, "not tcp port 21601", 1, netmask) < 0)
        {
            fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        }

        if (pcap_setfilter(handler, &bpf) < 0) { fprintf(stderr,"\nError setting the filter.\n"); }

        while(pcap_datalink(handler) == DLT_EN10MB && (sock->state() == QAbstractSocket::ConnectedState))
        {
            pcap_next_packet = pcap_next_ex(handler, &pckt_header, &pckt_data);
            if(pcap_next_packet > 0 && _CAP_ALLOWED_)
            {
                for(bpf_u_int32 i = 0 ; i < pckt_header->len ; i++)
                {
                    _QBA_.append(pckt_data[i]);
                }

                //qDebug() << _QBA_ << "\n\n\n";
                emit here_is_packet_to_send(qCompress(_QBA_, 9));
                _QBA_.clear();
            }
        }
    }

signals:
    void here_is_packet_to_send(QByteArray);
};

class AgentClient : public QThread
{
    Q_OBJECT

private:

    QObject *parent;

    /* ---------- U-INFO ---------- */
    DWORD level = 4;
    NET_API_STATUS nStatus;
    LPUSER_INFO_0 pBuf = NULL;
    LPUSER_INFO_4 pBuf4 = NULL;
    QString SRV;
    QString USER;

    /* ---------- CAP ---------- */
    bool _CAP_ALLOWED_ = true;
    pcap_t* handler;
    pcap_if* pcap_dev;
    const u_char *pckt_data;
    struct pcap_pkthdr *pckt_header;
    char ERRBUFF[PCAP_ERRBUF_SIZE];
    pcap_if_t* all_devs;
    pcap_if_t* single_dev;

    /* ---------- SOCK ---------- */
    QTcpSocket *_AG_CAP_CLI_SOCK_;
    QTcpSocket *_AG_CONTROL_SOCK;
    QByteArray _RESPONSE_;



public:

    AgentClient(QObject *p) : parent(p), SRV("localhost"), USER("Yazid") {

        _AG_CAP_CLI_SOCK_ = new QTcpSocket();
        _AG_CONTROL_SOCK = new QTcpSocket();
        QObject::connect(_AG_CAP_CLI_SOCK_, SIGNAL(connected()), this, SLOT(connected()));
        QObject::connect(_AG_CONTROL_SOCK, SIGNAL(connected()), this, SLOT(ctrl_connected()));

        //std::cout << "Appel constructeur agent" << std::endl;

        wchar_t *wc = reinterpret_cast<wchar_t*>(SRV.data());
        wchar_t *wc2 = reinterpret_cast<wchar_t*>(USER.data());

        nStatus = NetUserGetInfo(wc, wc2, level, (LPBYTE*)&pBuf);

        if (nStatus == NERR_Success)
        {
            if (pBuf != NULL)
            {
                pBuf4 = (LPUSER_INFO_4)pBuf;
                std::cout << "Bonjour agent " << QString::fromWCharArray(pBuf4->usri4_name).toStdString().c_str() << " !\n";
                std::cout << "Derniere connexion a ce PC: " << QDateTime::fromSecsSinceEpoch(pBuf4->usri4_last_logon).time().toString().toStdString() << "\n";
                std::cout << "Capacite de stockage: " << QString::number(pBuf4->usri4_max_storage).toStdString().c_str() << "\n";

            } else {
                std::cout << "[SPROTO] Buffer is empty" << std::endl;
            }
        } else {
            std::cout << "[SPROTO] Error while getting user info" << std::endl;
        }

        _AG_CAP_CLI_SOCK_->connectToHost("192.168.11.102", 21601);
        _AG_CONTROL_SOCK->connectToHost("192.168.11.102", 21602);

        QObject::connect(_AG_CONTROL_SOCK, SIGNAL(readyRead()), this, SLOT(read_and_process()));

        _AG_CONTROL_SOCK->write("HELLO SERVER");
        _AG_CONTROL_SOCK->waitForBytesWritten(3000);
        _AG_CONTROL_SOCK->write(QString::fromWCharArray(pBuf4->usri4_name).toStdString().c_str());
        _AG_CONTROL_SOCK->waitForBytesWritten(3000);
        _AG_CONTROL_SOCK->write(QDateTime::fromSecsSinceEpoch(pBuf4->usri4_last_logon).time().toString().toStdString().c_str());
        _AG_CONTROL_SOCK->waitForBytesWritten(3000);


    }

        void run() override
        {
            int get_local_devs = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devs, ERRBUFF);
            if(get_local_devs == -1) { std::cout << "Erreur" << std::endl; }

            std::cout << "\nCapture sur les interfaces suivantes: \n" << std::endl;
            single_dev = all_devs;
            while(single_dev != NULL)
            {
                std::cout << single_dev->description << std::endl;
                handler = pcap_open(single_dev->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 100, NULL, ERRBUFF);
                if(handler != NULL) { exit(-1); }

                CW_Agent_Thread* CWAT = new CW_Agent_Thread(handler, parent, _AG_CAP_CLI_SOCK_, single_dev);
                QObject::connect(CWAT, SIGNAL(here_is_packet_to_send(QByteArray)), this, SLOT(hop_(QByteArray)));
                CWAT->start();

                single_dev = single_dev->next;
            }
            pcap_freealldevs(all_devs);
        }

public slots:

    void read_and_process() {
        QByteArray _DATA_ =_AG_CONTROL_SOCK->readAll();
        //qDebug() << _DATA_ << "\n";

        if(_DATA_.contains("IDENTITY REQUEST"))
        {
            _RESPONSE_.append("name: ");
            _RESPONSE_.append(QString::fromWCharArray(pBuf4->usri4_name).toStdString().c_str());
            _AG_CONTROL_SOCK->write(_RESPONSE_);
            _AG_CONTROL_SOCK->waitForBytesWritten(3000);
        } else {
            if(_DATA_.contains("SIGLOCK"))
            {
                LockWorkStation();
            }
        }

    }

    void hop_(QByteArray qba_to_s)
    {
        _AG_CAP_CLI_SOCK_->write(qba_to_s);
        _AG_CAP_CLI_SOCK_->waitForBytesWritten(5000);
        this->thread()->msleep(1);
    }

    void connected()
    {
        std::cout << "Canal de capture etabli vers " << QHostAddress(_AG_CAP_CLI_SOCK_->peerAddress()).toString().toStdString() << ":" << _AG_CAP_CLI_SOCK_->peerPort() << std::endl;
    }

    void ctrl_connected()
    {
        std::cout << "Canal de controle etabli vers " << QHostAddress(_AG_CONTROL_SOCK->peerAddress()).toString().toStdString() << ":" << _AG_CONTROL_SOCK->peerPort() << std::endl;
    }

};

#endif // AGENTCLIENT_H
