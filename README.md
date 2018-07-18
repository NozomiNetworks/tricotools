# Tricotools
A collection of utilities and tools related to the **Triconex** hardware manufactured by Schneider Electric. Triconex products are a Safety Instrumented Systems (SIS) based on patented triple modular redundancy (TMR) industrial safety-shutdown technology.

# Wireshark dissector
The dissector for the TriStation protocol has been written in Lua to be portable and easy to use.

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
