#include <QCoreApplication>
#include "AgentClient.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << R"(
                                                                                      __      _
                                                                                    o'')}____//
                                                                                     `_/      )
                                                                                     (_(_/-(_/
                                             _____                 _        _
                                            / ____|               | |      | |
                                           | (___  _ __  _ __ ___ | |_ ___ | |_ _   _ _ __   ___
                                            \___ \| '_ \| '__/ _ \| __/ _ \| __| | | | '_ \ / _ \
                                            ____) | |_) | | | (_) | || (_) | |_| |_| | |_) |  __/
                                           |_____/| .__/|_|  \___/ \__\___/ \__|\__, | .__/ \___|
                                                  | |                            __/ | |
                                                  |_|                           |___/|_|    Yazid
)";

    QCoreApplication a(argc, argv);
    AgentClient *_SPROTOAC_ = new AgentClient(&a);
    _SPROTOAC_->start();

    return a.exec();
}
