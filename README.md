# OverflowWriteup
## Przebieg laboratorium
* Pierwszym krokiem było wykorzystanie oprogramowania nmap w celu rekonensanu aktywnego, użyto w tym celu komendy:
```
sudo nmap -sS -sV -sC <ip_address>
- sS - TCP SYN skan
- sV - sprawdzenie możliwosci występowania wersji oprogramowania na otwartym porcie
- sC - wykonanie podstawowych skryptów
```
Wynik skanowania
![image](https://user-images.githubusercontent.com/73962599/149634470-197cca16-da3c-4970-928c-172db46365bf.png)

Jak widać otwarte są porty 22, 25 i 80. Następne kroki będą realizowane na stronie WWW, która prezentuje się nastepująco:

![image](https://user-images.githubusercontent.com/73962599/149634622-f76b4f78-4271-497a-9934-a26a816c7c9f.png)

* Po zarejestrowaniu się i wejścu w zakładkę "Blog" można zauważyć listę podpowiedzi co należy zrobić by uzyskać dostęp do użytkownika root.

![image](https://user-images.githubusercontent.com/73962599/150023364-e0c7df52-fd4d-4886-a0f4-13080f2e1b3c.png)

* W kolejnym kroku próbowano uzyskać dostęp do konta administratora strony. W tym celu sprawdzono prosty atak SQLi, jednak bez skutku. Dlatego zdecydowano się na Oracle Padding attack z użyciem narzędzia [padBuster](https://github.com/AonCyberLabs/PadBuster) za pomocą komendy `./padBuster.pl http://overflow.htb (cookie) 8 -cookie auth=(cookie)` 

![image](https://user-images.githubusercontent.com/73962599/149636698-fc613b2d-301c-4a34-b0f8-3a058135b7f0.png)

* W wynikach bloku 1 szczególnie interesujące jest pole `Plain Text: user=lal`. Komendę powtórzono z dodatkową opcją `-plaintext user=admin` w celu uzyskania ciasteczka admina.

![image](https://user-images.githubusercontent.com/73962599/149636912-e399d736-e505-4740-a951-ab4734174b4a.png)

* Po podmianie ciasteczek mamy dostęp do użytkownika admin.

![image](https://user-images.githubusercontent.com/73962599/149636946-138768db-2de3-4c99-af4d-9815c7880d1d.png)

* W panelu admina widzimy stronę logowania do CMS Admin Panel. Po zbadaniu elementu zauważono podpięty skrypt `admin_last_login.js`, w którym jest podany link prawdopodobnie podatny na SQLi.

![image](https://user-images.githubusercontent.com/73962599/149636975-784bc842-d76a-4af9-8851-c50150925476.png)

![image](https://user-images.githubusercontent.com/73962599/149637059-57ebe086-bb1c-4f7d-a12e-a8afc1f8568d.png)

![image](https://user-images.githubusercontent.com/73962599/149637066-769c0071-f620-4c6e-ad28-ed2a14a71e84.png)

* Następnie sprawdzono SQLi wykorzystując narzędzie `sqlmap` podając cookie admina i listując bazy danych. Najciekawsze wydały się bazy o nzawie `cmsmsdb` oraz `Overflow`

![image](https://user-images.githubusercontent.com/73962599/149637180-d84b6b9b-53ac-4c27-bf35-09160f566db3.png)

![image](https://user-images.githubusercontent.com/73962599/149637278-d517db00-ac5d-43b9-9424-a0c045540109.png)

```
sqlmap -u http://overflow.htb/home/logs.php?name=admin --cookie="auth=BAitGdYuupMjA3gl1aFoOwAAAAAAAAAA" -D cmsmsdb --dump
```

![image](https://user-images.githubusercontent.com/73962599/149637312-4dd84c49-cf6c-49a6-8d7b-210408fb93a5.png)

* Po zdumpowaniu tabel i przejrzeniu zawartości, najciekawsza informacja wydała się w tabeli `cms_userplugins`, w której dostaliśmy informację na temat podstrony `devbuild-job.overflow.htb` 

![image](https://user-images.githubusercontent.com/73962599/149637388-3da4a3d1-673f-4ceb-900d-bcdc9affa32e.png)

* Po dodaniu adresu do `/etc/hosts`, stronę otworzono i ukazał się ekran logowania. Wykonano skan narzędziem `dirbuster` i zauwazono, że `/home/profile/index.php` ma odpowiedź 200, więc wpisano ją bezpośrednio do paska adresu co pozwoliło ominąć etap logowania

![image](https://user-images.githubusercontent.com/73962599/149637443-7d491b6f-0ec6-44ce-80da-e679e0e8110e.png)

![image](https://user-images.githubusercontent.com/73962599/149637451-ef47314e-637e-4f3f-a5dc-82ece6a89090.png)

![image](https://user-images.githubusercontent.com/73962599/149637566-69c9abd7-9348-40ca-9d80-840d046116ef.png)

* Po udanym wejściu na strone zauważono możliwość przesłania pliku na serwer. Skorzystano więc z narzędzia [CVE-2021-22204-exiftool](https://github.com/convisolabs/CVE-2021-22204-exiftool) do przesłania złośliwego obrazka, by uzyskać revers shell'a.

![image](https://user-images.githubusercontent.com/73962599/149637577-baa1464f-8fe7-4284-9707-0f078b33077b.png)

* Po zmodyfikowaniu skryptu (ustawieniu adresu ip w tun0 oraz portu, na którym będziemy nasłuchiwać) utworzono złośliwy plik

![image](https://user-images.githubusercontent.com/73962599/150513498-8c59984f-8d77-4ac6-a0e5-e37f2565070b.png)

* Po uruchomieniu netcata, po chwili dostaliśmy sesję użytkownika `www-data`

![image](https://user-images.githubusercontent.com/73962599/149637965-b72ad6b3-13db-46d2-825b-8b3951b41643.png)

* W katalogu `/var/www/config` znajdował się m.in. plik `db.php`, z którego wyczytano login i hasło użytkownika `developer`

![image](https://user-images.githubusercontent.com/73962599/149638001-4dc88791-1bbf-4000-b876-3103c085f65c.png)

![image](https://user-images.githubusercontent.com/73962599/149638240-fd7d3a9e-5d22-41ae-872e-a9753e18f11e.png)

* Po zalogowaniu się oraz wyświetleniu listy działających procesów, zauważono działający skrypt `/otp/commontask.sh` należący do użytkownika `tester`

![image](https://user-images.githubusercontent.com/73962599/149638457-b7121087-9231-4a93-b6b5-0ef845583430.png)

![image](https://user-images.githubusercontent.com/73962599/149638486-7207d509-1cf2-4d33-b1c6-539498d49f93.png)

* Po sprawdzeniu zawartości pliku `commontask.sh` widać, że program ma się wykonywać co minutę pobierając plik `task.sh` z `taskmanage.overflow.htb`. Zatem stworzono taki plik, który zwróci nam reverse shell'a dla użytkownika `tester`

![image](https://user-images.githubusercontent.com/73962599/149638703-c932668a-7113-40a8-9ab3-59b21e07b937.png)

* Uruchomiono również serwer http za pomocą pythona na naszej maszynie, dodano ip tej maszyny do pliku `/etc/hosts` na maszynie overflow i uruchomiono netcata w celu utworzenia sesji

![image](https://user-images.githubusercontent.com/73962599/149638661-eae185a1-ab0d-484f-8116-a4f9ce55f5d6.png)

![image](https://user-images.githubusercontent.com/73962599/149638677-0a680baa-c875-4e21-b557-ba88d478a439.png)

![image](https://user-images.githubusercontent.com/73962599/149638681-05deb309-bd67-4a33-9636-aead01f67f48.png)

* Po dostaniu się do użytkownika tester w jego katalogu domowym znajduje się rówież jego flaga w pliku user.txt

![image](https://user-images.githubusercontent.com/73962599/150569742-8a95a672-236c-4a50-a89e-f1ac6ebda0b6.png)

* W katalogu `/opt` znajdował się również folder `file_encrypt`, w którym był plik binarny o tej samej nazwie. Z racji braku pamięci na maszynie overflow pobrano ten plik w celu zbadania go za pomocą narzędzia `ghidra`

![image](https://user-images.githubusercontent.com/73962599/149639302-4bc70192-1658-4742-9278-c959fc222540.png)

* Funckja `check_pin()` zawierała funkcję `random()` która zwracała pin w celu porównania pinu, który wprowadzamy

![image](https://user-images.githubusercontent.com/73962599/149639892-0d1297fc-7c54-4fb5-bf40-85a40d9bab68.png)

* W celu znalezienia poprawnego pinu należy zrobić break funkcji random za pomocą `gdb`. Jak można zauwazyć polecenie tuż przed leave znajduje się na adresie `0x56555856` lub `random+57`. Robiąc break jeszcze raz, tym razem adresu `*random+57` można odczytać pin

![image](https://user-images.githubusercontent.com/73962599/149639884-58f64edb-f782-464c-9312-fa29a6fea251.png)

![image](https://user-images.githubusercontent.com/73962599/149639951-443beb0c-09b0-4abd-9f70-7e02f45e653b.png)

* Trzeba odnaleźć jeszcze `name` lub wykonać atak `buffer overflow`. Z racji tego, że niemożliwym jest znalezienie poprawnej nazwy zdecydowano się na drugą opcję.
* Jak można zauważyć, scanf do zmiennej name `(local_2c)` ma zarezerwowane 0x28 bajtów w hex lub 40 bajtów zapisanych dziesiętnie.
![image](https://user-images.githubusercontent.com/73962599/150521958-f2dc6c24-b161-4129-bed6-ba8a9770c310.png)
* Do wykonania ataku buffer overflow wykorzystany zostanie payload składający się z 44 znaków (40 bajtów zarezerwowane + 4 bajty, ponieważ rejestr ma taką wielkość dla pliku skompilowanego dla systemu 32 bitowego) + [XUV (adres 0x5655585b zapisany za pomocą little endian oraz przekonwertowany do textu)

* Kolejnym krokiem będzie przejęcie pliku `id_rsa` root'a. W tym celu uruchamiamy program `file_encrypt`, podajemy pin, a następnie stworzony payload. W tym momencie uruchamia się funkcja `encrypt()`, która prosi o input file. W tym miejscu podajemy jakikolwiek stworzony plik, w tym przypadku jest to plik `temp`. Drugim plikiem do podania jest `encrypted file`. Tutaj trzeba podać ścieżkę do pliku, w którym znajdze się przechwycony, zaszyfrowany xor'em plik id_rsa root'a. Ważne jest to, żeby nie wykonywać programu do końca (nie klikać enter przy podaniu "outputu". W drugim terminalu, należy użyć komendy `rm temp; ln -s /root/.ssh/id_rsa temp`, która stworzy dowiązanie symboliczne do pliku id_rsa. Gdy mamy przygotowane oba terminale, należy "dokończyć działanie pliku `file_encrypt`. Po wciśnięciu enter'a mamy 3 sekundy na wykonanie komendy tworzącej dowiązanie symboliczne.

![image](https://user-images.githubusercontent.com/73962599/150525521-d7b3da90-3f8b-49d5-a56d-820924a8a92b.png)

![image](https://user-images.githubusercontent.com/73962599/150018148-97ceefd0-f8b0-46ca-8aae-3be82fec5ecc.png)

![image](https://user-images.githubusercontent.com/73962599/150018716-5ffd61c6-e585-4892-83cb-756b64f9344a.png)

* By zdekodować plik zaszyfrowany xor'em należy go zaszyfrować jeszcze raz. Można użyć do tego jeszcze raz pliku `file_encrypt` lub użyć innej funkcji szyfrującej. Zdecydowano się na drugie rozwiązanie. Klucz szyfrujący `0x9b` również można odczytać z funkcji `encrypt()`

![image](https://user-images.githubusercontent.com/73962599/150538245-2fbd04ad-911b-4564-81b2-5d309a997c71.png)

![image](https://user-images.githubusercontent.com/73962599/150020639-fb07c6fa-cf87-499f-a5ee-90080c4d7f70.png)

* Po skopiowaniu zawartości id_rsa, użyto go do zalogowania się na maszynę jako root.

![image](https://user-images.githubusercontent.com/73962599/150020876-bdaa911a-3130-43af-860d-03157abcb0a3.png)


