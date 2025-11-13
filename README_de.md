# AirSnare (ehemals zizzania)

[English version](README.md)

AirSnare überwacht drahtlosen Netzwerkverkehr, sucht gezielt nach WPA-/WPA2-Handshakes und speichert nur die Frames, die für eine spätere Entschlüsselung nötig sind (ein Beacon, die EAPOL-Sequenz und relevante Datenframes). Um den Prozess zu beschleunigen, kann AirSnare IEEE 802.11 Deauthentication-Frames an ausgewählte Stationen senden, verwaltet Retransmits/Reassociations automatisch und begrenzt die Anzahl der gesendeten Frames pro Client.

![Screenshot](https://i.imgur.com/zGxPSTE.png)

## Beispiele

Interface in den RFMON-Modus auf Kanal 6 versetzen und nur den Verkehr der Stationen eines bestimmten Access Points mitschneiden (MACs beginnend mit `00:11:22` werden dabei ausgeschlossen):

```
airsnare -i wlan0 -c 6 -b AA:BB:CC:DD:EE:FF -x 00:11:22:33:44:55/ff:ff:ff:00:00:00 -w out.pcap
```

---

Passiv den Verkehr aller Stationen am aktuellen Kanal beobachten (Interface befindet sich bereits im RFMON-Modus):

```
airsnare -i wlan0 -n
```

---

Überflüssige Frames aus einer bestehenden pcap-Datei entfernen, dabei Handshakes schon nach den ersten zwei EAPOL-Nachrichten als vollständig betrachten (genug für Unicast):

```
airsnare -r in.pcap -x 00:11:22:33:44:55 -w out.pcap
```

## Setup

### Abhängigkeiten

Debian/Ubuntu:

```
sudo apt-get install libpcap-dev
```

macOS (Homebrew):

```
brew install libpcap wget
```

### Build

```
make -f config.Makefile
make
```

### Installation

AirSnare lässt sich direkt aus `src/` starten; Installation ist optional:

```
make install
make uninstall
```

## Konfiguration

AirSnare lädt Konfigurationsdateien **vor** den CLI-Argumenten. Jede spätere Quelle überschreibt frühere Werte:

1. `/etc/airsnare.conf` (systemweit, optional)
2. `~/.airsnarerc` (nutzerbezogen, optional)
3. Beliebig viele Dateien über `--config <pfad>`
4. Kommandozeile (hat oberste Priorität)

Das Format ist minimal: `schlüssel = wert` pro Zeile, Kommentare via `#` oder `;`. Strings dürfen in `'` oder `"` stehen, `~` wird zu `$HOME` expandiert. Beispielwerte findest du in `airsnare.conf.example`.

**Verfügbare Schlüssel**

| Schlüssel | Typ | Beschreibung / CLI-Entsprechung |
|-----------|-----|----------------------------------|
| `interface`, `input` | string | Live-Interface (`-i`) |
| `pcap`, `input_file`, `read_file` | string | Eingabedatei (`-r`) |
| `output`, `write_file` | string | Ausgabe-pcap (`-w`) |
| `channel` | int | Kanalnummer (`-c`) |
| `no_rfmon` | bool | RFMON-Setup überspringen (`-M`) |
| `passive` | bool | Passiver Modus (`-n`) |
| `deauth_count` | int | Anzahl Frames pro Burst (`-d`) |
| `deauth_attempts` | int | Maximale Versuche (`-a`) |
| `deauth_interval` | int | Sekunden zwischen Bursts (`-t`) |
| `dump_group_traffic` | bool | Broadcast/Multicast speichern (`-g`) |
| `early_quit` | bool | Nach erstem Handshake beenden (`-q`) |
| `max_handshake` | int 2‑4 | Anzahl benötigter EAPOL-Messages (`-2`/`-3`) |
| `bssid_include` / `bssid_exclude` | csv | MAC-/Maskenlisten (`-b`/`-B`) |
| `station_include` / `station_exclude` | csv | Stationen whitelisten/blacklisten (`-s`/`-S`) |
| `bssid_exclude_first` / `station_exclude_first` | bool | Reihenfolge für Filter (`-x b` / `-x s`) |
| `log_level` | string/int | `error`, `info`, `warn`, `debug`, `trace` bzw. `0-4` (`-v`) |

CSV-Werte sind komma-getrennt (`MAC[/Maske], MAC`). Booleans akzeptieren `true/false`, `yes/no`, `on/off`, `0/1`. Fehlerhafte Einträge stoppen nur das Laden der jeweiligen Datei und melden Dateiname + Zeilennummer.

**Schnellstart**

```
cp airsnare.conf.example ~/.airsnarerc
$EDITOR ~/.airsnarerc
./src/airsnare --config ~/.airsnarerc -n
```

So lassen sich vorkonfigurierte Profile pflegen, während einzelne Flags (z.B. `-v`) weiterhin aus der CLI kommen.

## macOS-Hinweise

Kanalwechsel muss manuell erfolgen:

```
ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport
sudo airport --disassociate
sudo airport --channel=<kanal>
```

## Code-Struktur

```
src/
|-- airsnare.c              # Programmeinstieg, Lebenszyklus
|
|-- handler.c/h             # Handler-Setup, pcap, BPF, Mainloop
|-- dissector.c/h           # Frame-Parsen & Filter
|-- handshake.c/h           # WPA-Handshakes verwalten
|-- killer.c/h              # Deauth-Injektion
|-- dispatcher.c/h          # Signal-Handling, Killer-Trigger
|
|-- clients.c/h             # Stations-Tracking
|-- bsss.c/h                # Access-Point-Tracking
|-- members.c/h             # MAC-Listen (Whitelist/Blacklist)
|
|-- ieee802.c/h             # Protokolldefinitionen
|-- config.c/h              # Konfiguration laden & Prioritäten
|-- options.c/h             # CLI & Konfig-Zusammenführung
|-- terminal.c/h            # Ausgabe & Statistiken
|-- util.c/h                # Privileg-Themen
|-- iface.c/h               # Interface-spezifische Helfer
|
|-- params.h                # Laufzeit-Konstanten
|-- release.h               # Versionsinfos
`-- endian.h                # Byteorder-Makros
```
