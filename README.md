# tricotools
Collection of utilities and tools related with the **Triconex** hardware manufactured by Schneider Electric. Triconex products are a Safety Instrumented Systems (SIS) based on patented Triple modular redundancy (TMR) industrial safety-shutdown technology.

# Wireshark dissector
The dissector for the TriStation protocol has been written in LUA to be portable and easy to use.

## Installation
The LUA script is natively supported by Wireshark and no dependencies are required in order to use it. The script needs to be placed in the right directory depending on the operating system in use. Below are reported the working paths used during the development:

* Linux / MacOS: ```~/.config/wireshark/plugins```
* Windows: ```%appdata%\Wireshark\plugins```

Note that in some systems the plugin folder could be missing. To fix the issue, just create it manually placing the LUA script inside after the creation.

More detailed information about the plugin installation can be found at the official web page:
[https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)

## Features
The dissector is able to interprete the TriStation protocol function codes populating the description fields in according with the specific analysed packets. The user can easily dive into the packet stream getting the following benefits:
* Communication’s direction
* Function code translated in descriptive text
* Extraction of the transmitted PLC programs
* TRITON malware detection

The dissector is able to automatically detect TRITON malware using specific indicators obtained during the malware analysis performed in the laboratory. 
We provided a **stripped** PCAP file captured during a real execution of the malware to demonstrate the described features.