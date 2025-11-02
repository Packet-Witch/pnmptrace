# pnmptrace
A command line utility which reads PNMP-format JSON reports from stdin and outputs them to stdout in familiar AX25 "packet trace" format.


          "PNMPTRACE" JSON to AX25 Packet Trace Decoder

                    User Manual For Version 1.0


### What is PNMPTRACE? ###

   PNMPTRACE is a free open-source command line program which converts
   PNMP-format packet traces from JSON to a familiar ASCII "trace"
   format.

### What is PNMP? ###

   PNMP is the **Packet Network Monitoring Project**. The PNMP server
   receives packet traces and status data from participating XRouter
   and BPQ nodes, for the purposes of network monotoring, analysis,
   fault-finding and planning.

   The server, currently at 'node-api.packet.oarc.uk', makes the data
   available in a variety of forms, including an MQTT "hoseline" of raw
   data from the nodes (aka "reporters").  It is this data, from the
   endpoint at 'node-api.packet.oarc.uk/in/udp' that PNPMTRACE uses.

 ### Requirements ###

   GCC to compile the program.

   mosquitto_sub (or any other suitable MQTT client). You can install
   this using 'sudo apt install mosquitto-clients'

### Notes ###

   This document assumes the use of Linux, and the MQTT client
   'mosquitto_sub', but any MQTT client which outputs JSON to stdout
   could be used instead.

### How to Compile PNMPTRACE ###

   Put pnmptrace.c into a directory of your choice.

   Open a terminal and change into that directory.

   Type: gcc -Wall -o "pnmptrace" "pnmptrace.c"

   Type: "ls" and you should see the compiled executable 'pnmptrace'.

   You can leave the executable where it is, or move it to the /bin
   directory, which will allow it to be run from anywhere without
   prepending "./".  You can move the executable like this:

       sudo mv pnmptrace /bin

### How To Use PNMPTRACE ###

   Run mosquitto_sub, specifying the host and topic like so:

      mosquitto_sub -h node-api.packet.oarc.uk -t in/udp

   You should see a constant stream of JSON data. If so, you can stop
   mosquitto_sub and move to the next step.  If you don't see any JSON,
   stop mosquitto_sub and re-check your command.

   Pipe the output of mosquitto_sub into PNMPTRACE like this:

      mosquitto_sub -h node-api.packet.oarc.uk -t in/udp | ./pnmptrace
      
        (omit the "./" if you moved pnptrace to /bin)

   You should now see the packet traces in a more familiar form.  The
   exact format can be tweaked using various command line options, as
   detailed in the next section.

   To read the MQTT from a file instead of mosquitto_sub, you would use
   a command like this, to pipe the output of "cat" into the input of
   pnmptrace:

      cat mqtt.txt | ./pnmptrace

   You may wish to apply some "filters" to restrict the amount of data
   being displayed.  For instance, you might only be interested in UI
   frames, or frames from a particular station, or frames carrying a
   paticular protocol such as IP.

### Filters and Display Options ###

   These are specified as arguments to the program. They cannot (yet)
   be changed on the fly.

   #### Summary of Options ####

     -3              Don't trace NetRom layer 3 or above
     -4              Don't trace NetRom layer 4 or above
     -a <callsign>   Show ALL frames to or from <callsign>
     -c              Don't colourise the traces
     -C              Include colour information in capture file
     -f <callsign>   Show only frames addressed FROM <callsign>
     -h              Show this message and exit
     -H              Show header on separate line to trace
     -i              Don't trace contents of INP3 routing unicasts
     -j              Show the raw JSON before each trace
     -k              Don't show L3RTT info field
     -l              Suppress blank line between traces
     -n              Don't trace contents of NetRom nodes broadcasts
     -o <file>       Output trace to <file>
     -p <portnum>    Show reports only from <portnum>
     -P <protocol>   Show only frames with this L3 protocol
     -q              No display when capturing to file (quiet)
     -r <callsign>   Show reports only from <callsign>
     -s              Suppress time stamp
     -t <callsign>   Show only frames addressed TO <callsign>
     -T <frametype>  Show only this AX25 frametype, e.g. "-T UI"
     -u              Don't display UI frames
     -w <width>      Display width (default 80 cols)
     -W              Enable warnings of missing/bad JSON fields

   More than one option can be specified, but some combinations are
   pointless.  For example, if -3 is specified -i and -n are redundant.

   #### Display Options: ####

     -c
        Don't colourise the traces.  By default, traces are coloured
        according to whether the link is RF or internet, and whether
        the direction is "sent" or "received".  RF-originated traces
        are displayed in pure red (transmit) or green (receive).
        Internet-originated traces are displayed in pink (transmit) or
        turquoise (receive). 

     -C
        Include colour information in capture file.  This is off by
        default, and is ignored if the '-c' option is specified.
        Including colour information in the file allows it to be
        played back in colour, but makes it harder to read with a text
        editor.

     -H
        Show header (metadata) on a separate line to trace.  This is
        off by default, as most people seem to prefer "one line per
        packet".  If enabled, the display is less cryptic and includes
        more information.

     -j
        Show the raw JSON prior to each trace.  This is off by default.
        If enabled, the JSON data for each trace is displayed first,
        followed by the decoded trace.  Included mainly for debugging.

     -l
        Suppress the blank line between traces.  Off by default.
        Normally a blank line is output between each packet trace for
        clarity.  However some people like a more cluttered display,
        hence this option.

     -o <filename>
        Output the packet traces to <filename>.  If enabled, everything
        that is displayed on screen is echoed to a capture file, whose
        path/name is specified by this option.  The file is opened in
        "overwrite" mode.  While capturing, the screen output can be
        suppressed using the '-q' (quiet) option below.

     -q
        Suppresses the display while capturing to file.

     -s
        Suppress the packet time stamp.  Normally each packet trace
        if prefixed with a time stamp of the form HH:MM:SS.  These
        timestamps are generated by the reporting nodes, not by the
        server, so there may be time differences between them.

     -w <width>
        Specify the display width (default 80 columns).  Most traces
        should fit within 80 columns, but INP3 traces which include
        several INP3 options might exceed this width.  By default,
        these are neatly line-wrapped to fit 80 columns.  If you have a
        wider display window you can specify the width using this
        option.  The display will then line-wrap to fit the specified
        width.  This is intended for displays wider than 80 columns,
        not narrower.

     -W
        Enable warnings of missing or bad JSON fields.  This is mainly
        intended for debugging purposes.

   Filter Options:

     -3
        Don't trace NetRom layer 3 or above.  If this option is
        specified, packets containing NetRom layer 3/4 information,
        including NODES broadcasts and INP3 data, will end with
        "NET/ROM" and won't be traced any further.  You might use this
        if for example you are only interested in the layer 2 data.
        See also "-i", "-n" and "-4".

     -4
        Don't trace NetRom layer 4 or above.  If this option is
        specified, NetRom layer 4 headers or protocol extensions are
        not traced.

     -a <callsign>
        Show ALL frames to or from <callsign>.  If this filter is
        specified, ONLY those frames which have AX25 source or
        destination callsigns matching <callsign> are displayed.  This
        can be used to watch all traffic into or out of a specific
        node.

     -f <callsign>
        Show only frames addressed FROM <callsign>.  If this filter is
        specified, ONLY those frames whose AX25 source callsign matches   
        <callsign> are displayed.  This filter can be combined with
        other options for even tighter filtering.

     -i
        Don't trace contents of INP3 routing unicasts.  INP3 unicasts
        can occupy a lot of space on screen. If you don't need to see
        what they contain, the '-i' option suppresses decoding, so
        all that is displayed is "NET/ROM INP3".

     -k
        Don't show L3RTT info field.  The payload of an L3RTT frame can
        be up to 236 bytes, much of which is empty space. This wraps
        untidily, so the '-k' option can be used to suppress it.

     -n
        Don't trace contents of NetRom 'NODES' broadcasts.  If this
        option is used, nodes broadcasts display only "NET/ROM NODES".

     -p <portnum>
        Show reports only from <portnum>.  This filter is intended for
        use in conjunction with the '-r', '-t', '-f' or '-a' filters.
        For example, "r G8PZT -p 5" would show everything received or
        sent on G8PZT's port 5.  

     -P <protocol>
        Show only frames with the specified L3 protocol. For example
        "-P IP" shows only IP over AX25 frames.  The recognised
        protocols are as f0llows:

        Mnemonic    Meaning
        --------------------------------------------------------
        "SEG"       Intermediate segment of a fragmented packet
        "DATA"      No layer 3, i.e. payload contains normal data
        "NET/ROM"   Payload contains NetRom/INP3 information
        "IP"        Payload contains IP datagram or part thereof
        "ARP"       Payload contains ARP data
        "FLEXNET"   Payload contains Flexnet protocol
        "?"         Unknown layer 3 protocol

     -r <callsign>
        Show reports only from <callsign>.  This filters traffic by the
        "reporter" callsign, not the AX25 "to" or "from" fields. For
        example "-r G8PZT" shows only the frames sent or overheard by
        node G8PZT.

     -t <callsign>
        Show only frames addressed TO <callsign>.  If this filter is
        specified, ONLY those frames whose AX25 destination callsign
        matches <callsign> will be displayed.  Note that the same frame
        may be reported by more than one node.
     
     -T <frametype>
        Show only frames with the specified AX25 frametype.  For example
        "-T UI". The recognised frame types are as follows:

        Mnemonic  Meaning
        ---------------------------------------------------
        "SABME"   Set Asynchronous Balanced Mode Extended
        "C"       Non-extended connnect request (AKA SABM)
        "D"       Disconnect Request
        "DM"      Disconnected Mode / Busy
        "UA"      Unnumbered Acknowledgement
        "UI"      Unnumbered Information frame
        "I"       Numbered information frame
        "FRMR"    Frame Reject (serious error)
        "RR"      Receiver Ready
        "RNR"     Receiver Not Ready
        "REJ"     Reject (Frame not the expected one)
        "SREJ"    Selective Reject
        "TEST"    Test of data link
        "XID"     Exchange Identification
        "?"       Unknown type

     -u
        Don't display UI frames.  This option may be useful if you
        don't want to see beacons, APRS data, or nodes broadcasts.


Copyright (c) 2025 Paula Dowie
