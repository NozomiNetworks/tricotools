# Tricotools
A collection of utilities and tools related to the **Triconex** hardware manufactured by Schneider Electric. Triconex products are a Safety Instrumented Systems (SIS) based on patented triple modular redundancy (TMR) industrial safety-shutdown technology.

# TriStation dissector
The Wireshark dissector for the TriStation protocol has been written in Lua to be portable and easy to use.

## Installation
The Lua script is natively supported by Wireshark and there are no required dependencies for using it. The script needs to be placed in the right directory depending on the operating system used. Below are the reported working paths used during development:

* Linux / MacOS: ```~/.config/wireshark/plugins```
* Windows: ```%appdata%\Wireshark\plugins```

Note that in some systems the plug-in folder could be missing. To fix this issue, just create it manually and place the Lua script in it.

More detailed information about plug-in installation can be found at the official web page:
[https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)

## Features
The dissector interprets the TriStation protocol function codes, populating the description fields for the specific analysed packets. The user can easily investigate the packet stream for:
* The direction of communication
* Function codes translated as descriptive text
* Extraction of transmitted PLC programs
* TRITON malware detection

The dissector automatically detects TRITON malware using specific indicators obtained during malware analysis performed in the laboratory. We provide a **stripped** PCAP file captured during real execution of the malware to demonstrate the described features. 

We would like to emphasize that the functionality of the dissector is the result of our malware analysis and reflects the attackers’ reverse engineering of the TriStation protocol.

# Triconex Honeypot
The Triconex Honeypot tool can be used by defense teams to simulate SIS controllers with particular system configurations, using them to detect reconnaissance scans and capture malicious payloads. It can therefore play a useful role in detecting unknown traffic targeting a SIS network.

## Dependencies
The python script requires the library ```crcmod```

* Linux / MacOS: ```pip install crcmod```

## Features
The tool simulates the controller’s behavior, convincing the Scheider Diagnostic Tool (software used to test it during our analysis) that we are a real controller sending its status, including:
* Controller version
* Controller status
* Controller memory
* Chassis type
* Connected modules
* Status LEDs
* LED type and color
* Hardware key position (RUN/STOP/PROGRAM)
* Project name
* Modules configuration match/mismatch (project  chassis)

Although the script is currently only a proof-of-concept, it can be expanded to support an extensive number of functions. Its realism can be increased to the point where it is indistinguishable from a real controller. In addition, the script can be executed by a regular, inexpensive computer attached to the network.
