Autor: Šimon Kadnár
Login: xkadna00
Dátum: 11.11.2022

Popis:
Program analyzuje súbory typu ".pcacp". Z nich postupne získava zachytenú komunikáciu (packety), ktoré ukladá do takzvaných "flowov"
(packety s rovnakími vlastnostami ako sú Protokol, Tos, SrcIP, DstIP, SrcPort, DstPort).
Tie odosiela na zadaný alebo základný NetFlowColecctor server.

Obmedzenia:
Nepodporuje adresu ipv6.

Spustenie:
./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]

-f <file> meno analyzovaného súboru v prípade, že nie je zadaný parameter \-f vstup sa očakáva ́zo STDIN.
-c <neflow collector:port> IP adresa alebo hostname NetFlow kolektoru pokiaľ nie je zadaný parameter –c
tak IP je nastavená na 127.0.0.1:2055.
-a <active timer> doba v sekundách po ktorej budú aktívne záznamy exportované na kolektor v prípade, že
nieje uvedený parameter –a, je active timer nastavený na 60s.
-i <seconds> doba v sekundách od príchodu posledného packetu ktorá ak bude prekročená tak budú neaktívne záznamy exportované na kolektor, 
ak nie je zadaný parameter –i východzia hodnota je nastavenána 10s.
-m <count> velikost flow-cache. Pri dosiahnutí maximálnej velikosti dôjde k exportu najstaršieho záznamu v cachy
na kolektor ak nieje -m zadané východzia hdonota je 1024.

Súbory: flow.c, makefile, manual.pdf, flow.1s