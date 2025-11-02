/*
 * PNMPTRACE - A JSON to AX25 Packet Trace Decoder for the experimental
 *             Packet Network Monitoring Project (PNMP).
 *
 * Copyright (C) 2025 Paula Dowie G8PZT.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 *
 ***********************************************************************
 *
 * Purpose:
 *
 *    This program reads serialised JSON data from stdin, and outputs
 *    it to stdout and/or file in a familiar "packet trace" format.
 *
 *    The input JSON is expected to be in the PNMP (Packet Network
 *    Monitoring Project) format, as output by XRouter and BPQ nodes.
 *
 *    The data source may be the output of an MQTT client, or a file
 *    containing previously downloaded JSON. The MQTT client may connect
 *    with the main PNMP server for a network-wide view, or XRouter's
 *    internal MQTT broker for local monitoring.
 *
 *    The output format and packet filtering can be changed by command
 *    line options.
 *
 *
 * Usage:
 *
 *    pnpmtrace [options]
 *
 *    (use the "-help" option to list options)
 *
 *
 * Examples:
 *
 *    cat mqtt.txt | pnmptrace -H -n
 *
 *    mosquitto_sub -h node-api.packet.oarc.uk -t in/udp | pnmptrace
 *
 *
 * Limitations:
 *
 *    THIS IS ONLY A RUDIMENTARY JSON PARSER!  It is sufficient for the
 *    purpose of decoding JSON from the Packet Network Monitoring
 *    Project server, and nothing else.  One of the limitations is that
 *    it can not drill down into nested objects.
 *
 *
 * Versions:
 *
 *    Ver   Date     Comments
 *    -----------------------------------------------------------------
 *    1.0   24/10/25 Quick and dirty proof of concept. Decodes only
 *                   "L2Trace" objects. Requires an MQTT client such as
 *                   "mosquitto_sub" to download the JSON from the
 *                   server to stdout.
 *
 * To-Do:
 *
 *    - Possibly include an MQTT client, to make this self-contained,
 *      although that would prevent the program from using other
 *      data sources.
 *
 *    - Wildcard callsign filtering, if it would be any use?
 *
 *    - Filtering on multiple callsigns, e.g. -t g8pzt*,KIDDER*,M1BFP-1
 *
 *    - Filter by multiple frame types simultaneously, e.g. "-T I,UI"
 *
 *    - Decode L3RTT frame payload.
 *
 *    - Trace other report types when they have been implemented, e.g.
 *      where "@type" is "L3Trace", "L4Trace", "IpTrace" etc.
 *
 *    - Maybe someone could convert this to RUST, SLIME, PLURP or
 *      whatever strange language is the flavour of the moment, because
 *      nobody understands "C" any more :-)
 *
 * Notes:
 *
 *    This source is best viewed with a text editor such as geany or
 *    featherpad which colourises different code elements such as
 *    comments and strings.
 *
 *    Yes I know JSON field names should ideally be case sensitive, but
 *    the source data isn't always consistent!  Therefore case
 *    independent matching had to be used.
 *
 *    The terms "field" and "object" may not be consistent. It was a
 *    single-afternoon project.  Feel free to correct it!
 *
 *    No attempt has been made to optimise the code, to make it
 *    efficient, or pretty. It just does the job it was intended for.
 *
 *    Page width is 72 characters, as horizontal scrolling sucks.
 *
 *    I *know* that my coding style is not industry standard, so don't
 *    bother telling me. If you don't like it, tough! It's all mine,
 *    and it works for me.  If you can do better, why haven't you
 *    already done it? :-p
 * */

#define _GNU_SOURCE  // Required for strcasestr()

#ifdef WIN32
#include <windows.h>
#include <shlwapi.h>
#define strcasestr StrStrI
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

static char VERSION[] = "1.0";
static char Margin[] = "\n    ";  // Left margin for L3/L4 layers

/* If filters are populated, they restrict the display to frames whose
 * fields match the filters. Unpopulated filters have no effect. The
 * compiler should set all these to null strings
 * */
static char ReportFilter [16];   // Callsign to accept reports from
static char SrcFilter [16];      // Source callsign filter
static char DstFilter [16];      // Destination callsign filter
static char AllFilter [16];      // Callsign to filter to/from
static char ProtoFilter [16];    // Protocol to filter by
static char TypeFilter [16];     // For filtering by L2Type
static int  PortFilter = 0;      // For filtering by port number
static int  DisplayWidth = 80;

// TraceFlags control display options & filters
static int  TraceFlags = 0x7ff;

#define  TRACE_UI       0x01     // Unnumbered information frames (on)
#define  TRACE_NETROM   0x02     // Trace Netrom L3/L4 layers (on)
#define  TRACE_L3RTT    0x04     // Show Info field of L3RTT (on)
#define  TRACE_NODES    0x08     // Trace into NODES broadcasts (on)
#define  TRACE_INP3     0x10     // Trace into INP3 unicasts (on)
#define  TRACE_L4       0x20     // Trace NetRom L4 headers (on)
#define  TRACE_IP       0x40     // Trace IP headers (on)
#define  TRACE_ARP      0x80     // Trace ARP packets (on)
#define  TRACE_COLOR    0x100    // Trace in colour (on)
#define  TRACE_STAMP    0x200    // Timestamp the trace (on)
#define  TRACE_LBRK     0x400    // Line break between traces (on)
#define  TRACE_HDRLIN   0x800    // Header & trace separate (off)
#define  TRACE_JSON     0x1000   // Display JSON prior to trace (off)
#define  TRACE_QUIET    0x2000   // Output to file only, no echo (off)
#define  TRACE_COLOR2FILE  0x4000   // Send colour to file (off)
#define  TRACE_WARNINGS 0x8000   // Display warnings of bad fields

static char CaptureFile [256];   // Capture file name
static FILE *FpCapture = NULL;   // For capturing output to file


//######################################################################
//                         JSON FUNCTIONS
//######################################################################

/**********************************************************************/
/* Purpose:    Find a named JSON object by name
 * Called by:  json_findArray() and json_getValue()
 * Arguments:  Pointer to serialised JSON object string. Object name.
 * Actions:    Performs a case-independent sliding match, looking for
 *             the object name (including surrounding quotes) in the
 *             serialised JSON.  If found, the pointer is advanced over
 *             the name, the colon, and any whitespace, until the start
 *             of the object's value. If the object name is not found,
 *             or there is no colon after the nem, NULL is returned.
 * Affects:    Nothing
 * Returns:    Pointer to the start of the object's value in "json", or
 *             NULL if the object is not found.
 * Notes:      Name is case independent.
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static char *json_findObject (const char *json, const char *name)
   {
   char  tmp [80], *cp;

   sprintf (tmp, "\"%s\"", name);

   if ((cp = strcasestr (json, tmp)) == NULL)
      return (NULL); // Name not found

   cp++; // Skip opening quote of the name

   while (*cp && *cp != '"') cp++;  // find end of name

   while (*cp && *cp != ':') cp++;   // find the colon

   if (*cp != ':') return (NULL);   // No colon - so not a name

   cp++; // skip the colon

   while (isspace (*cp)) cp++;   // Skip space after colon

   return (cp);   // Points at the object's value
   }

/**********************************************************************/
/* Purpose:    Find a named JSON array by name.
 * Called by:  trace_nodes() and trace_inp3().
 * Arguments:  Pointer to serialised JSON object string. Array name.
 * Actions:    Performs a case-independent sliding match looking for the
 *             array name in the serialised JSON. If found, checks that
 *             the name actually belongs to an array.
 * Affects:    Nothing.
 * Returns:    Pointer to the opening square bracket in the "json"
 *             string, or NULL if the array is not found.
 * Notes:      Name is case independent.
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static char *json_findArray (const char *json, char *name)
   {
   char  *cp;

   if ((cp = json_findObject (json, name)) == NULL) return (NULL);

   if (*cp != '[') return (NULL);

   return (cp);   // Point at opening bracket
   }

/**********************************************************************/
/* Purpose:    Get the value of a named JSON "field"
 * Called by:  Many places!
 * Arguments:  Pointer to serialised JSON object string, field name,
 *             Pointer to a string to receive the result, maximum chars
 *             to copy to result string.
 * Actions:    If the field is found, its string value, up to a maximum
 *             of "maxchars" is copied to the string pointed by "result"
 *             The quotes surrouunding string values are not copied.
 * Affects:    The string pointed by "result".
 * Returns:    Pointer to the first character after the field's value,
 *             or NULL if the field was not found.
 * Notes:      x
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static char *json_getValue (const char *json, const char *name,
   char *result, int maxlen)
   {
   char  *cp;
   int   string = 0;

   if ((cp = json_findObject (json, name)) == NULL)
      return (NULL); // Name not found

   if (*cp == '"')   // If the first char of the value is a quote,
      {
      string = 1;    // it's a string literal.
      cp++;          // Skip the quote character to point at value
      }

   if (string)       // If it's a string literal
      {
      while (*cp && *cp != '"')  // Copy everything between the quotes
         {
         if (maxlen-- > 0) *result++ = *cp;
         cp++;
         }
      }
   else  // Not a string literal, probably number or boolean
      {
      // Copy the value to "result"
      while (*cp && (*cp == '-' || *cp == '.' || isalnum (*cp)))
         {
         if (maxlen-- > 0) *result++ = *cp;
         cp++;
         }
      }

   *result = 0;   // Terminate the result string

   return (cp+1); // Pointer to first char AFTER the value
   }

/**********************************************************************/
/* Purpose:    Get next JSON object from an array of objects
 * Called by:  trace_inp3() only. Ought to be used by decde_nodes()!
 * Arguments:  Pointer to a string containing serialised array, pointer
 *             to a string buffer to receive the object, maximum number
 *             of characters to copy.
 * Actions:    Ignores curent object and finds start of next, then
 *             copies the found object into "buffer", including its
 *             opening and closing braces.
 * Affects:    Contents of the string pointed by "buffer".
 * Returns:    Pointer to the opening brace of the found array element,
 *             or NULL if no next object found.
 * Notes:      Flat arrays of simple objects only. Does not allow braces
 *             within object values.
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static const char *json_getNextArrayElement (const char *json,
   char *buffer, int maxlen)
   {
   const char  *cp = json;

   // Find end of current element
   while (*cp && *cp != '}' && *cp != ']') cp++;

   if (*cp != '}') return (NULL);   // Didn't find end

   // Find start of next element
   while (*cp && *cp != '{' && *cp != ']') cp++;

   if (*cp != '{') return (NULL); // No next element

   json = cp;  // Remember pointer to start of element

   // Copy up to "maxlen" characters to "buffer", including braces.
   while (*cp && maxlen-- > 0)
      {
      *buffer++ = *cp;
      if (*cp == '}') break;
      cp++;
      }
   *buffer = 0;   // terminate the output string

   return (json); // Pointer to start of element
   }



//######################################################################
//                       PACKET TRACE FUNCTIONS
//######################################################################

/**********************************************************************/
/* Purpose:    Output to user and optional capture file
 * Called by:  Most functions.
 * Arguments:  Format string plus zero or more additional fields
 * Actions:    Prints the data to a string, then outputs it to screen
 *             (stdout) and/or the capture file.
 * Affects:    stdout, capture file or both.
 * Returns:    Number of characters printed.
 * Notes:      The output string must not exceed 4095 bytes, but that is
 *             highly unlikely to happen. Most calls only output a few
 *             characters.
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static int uprintf (char *fmt, ...)
   {
   char buff [4096];
   va_list arg;

   va_start (arg, fmt);
   vsprintf (buff, fmt, arg);
   va_end (arg);

   // Output to capture file if it is open
   if (FpCapture)
      {
      fputs (buff, FpCapture);
      fflush (FpCapture);
      }

   // Output to stdio if not in "quiet" mode
   if ((TraceFlags & TRACE_QUIET) == 0) fputs (buff, stdout);

   return (strlen (buff));
   }


/**********************************************************************/
/* Purpose:    Decode and display a 'NODES' broadcast.
 * Called by:  trace_netromRoutingInfo() only.
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    Displays the alias of the node making the broadcast,
 *             then loops through the "nodes" array, displaying details
 *             of each route.
 * Affects:    stdout only
 * Returns:    None
 * Notes:      Assumes "fromAlias" appears before "nodes" in the JSON
 *             string. This is necessary because the JSON parser is
 *             crude and case insensitive. It cannot distinguish between
 *             the field *name* "nodes" and the field *value* "NODES"
 *             which appears earlier in the string. This could be fixed
 *             by a better parser.
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_nodes (const char *json)
   {
   char  tmp [80], *cp;

   if ((TraceFlags & TRACE_NODES) == 0)
      {
      uprintf (" NODES Broadcast");
      return; // Not wanted
      }

   if ((cp = json_getValue (json, "fromAlias", tmp, 6)) == NULL)
      {
      if (TraceFlags & TRACE_WARNINGS)
         uprintf (" [missing 'fromAlias']");
      return;
      }

   uprintf ("%sNODES Broadcast from %s:", Margin, tmp);

   if ((cp = json_findArray (cp, "nodes")) == NULL)
      {
      if (TraceFlags & TRACE_WARNINGS)
         uprintf (" [missing 'nodes' array]");
      return;
      }

   // cp is pointing at the opening square bracket of nodes array
   while (*cp)
      {
      // Format is "GE8PZT:BBS64 via GE8PZT qlty=20"
      if (json_getValue (cp, "call", tmp, 9))
         uprintf ("%s%s", Margin, tmp);

      if (json_getValue (cp, "alias", tmp, 6))
         uprintf (":%s", tmp);

      if (json_getValue (cp, "via", tmp, 9))
         uprintf (" via %s", tmp);

      if (json_getValue (cp, "qual", tmp, 3))
         uprintf (" qlty=%s", tmp);

      while (*cp && *cp != '}') cp++;   // find end of node object
      if (*cp) cp++;
      }
   }

static int wrap (void)
   {
   uprintf ("%s    ", Margin);
   return (8);
   }

/**********************************************************************/
/* Purpose:    Decode and display an INP3 routing unicast
 * Called by:  trace_netromRoutingInfo() only.
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    Loops through the "nodes" array, displaying details
 *             of each route.
 * Affects:    stdout only.
 * Returns:    None
 * Notes:      x
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_inp3 (const char *json)
   {
   char        object [1024], tmp [80];
   const char  *cp;

   if ((TraceFlags & TRACE_INP3) == 0)
      {
      uprintf (" INP3");
      return;
      }

   uprintf ("%sINP3 Routing Unicast:", Margin);

   if ((cp = json_findArray (json, "nodes")) == NULL)
      {
      if (TraceFlags & TRACE_WARNINGS)
         uprintf (" [missing 'nodes' array]");
      return;
      }

   // cp is now pointing at the opening square bracket of nodes array

   while ((cp = json_getNextArrayElement (cp, object, 1023)) != NULL)
      {
      int   cols = 0;

      // Minimum format is "GB7BDH    hp=2   tt=3"

      if (json_getValue (object, "call", tmp, 9))
         cols += uprintf ("%s%-9s", Margin, tmp);

      if (json_getValue (object, "hops", tmp, 2))
         cols += uprintf ("  hp=%-2s", tmp);

      if (json_getValue (object, "tt", tmp, 5))
         cols += uprintf ("  tt=%-5s", tmp);

      // Optional fields
      // "Alias=SWINDN 5128.75N 71582600.46E S/W=XRPi NODE PMS XRCHAT Ver=504k 25/10 06:20

      if (json_getValue (object, "alias", tmp, 6))
         cols += uprintf ("  Alias=%-6s", tmp);

      if (json_getValue (object, "latitude", tmp, 20))
         cols += uprintf (" %s", tmp);

       if (json_getValue (object, "longitude", tmp, 20))
         cols += uprintf (" %s", tmp);

      if (json_getValue (object, "software", tmp, 20))
         cols += uprintf (" S/W=%s", tmp);

      // If could overflow 80-col line after this point

      if (json_getValue (object, "version", tmp, 10))
         {
         if (cols+2+strlen (tmp) >= DisplayWidth) cols = wrap ();
         cols += uprintf (" v%s", tmp);
         }

      if (json_getValue (object, "isNode", tmp, 5)
      && strcmp (tmp, "true") == 0)
         {
         if ((cols + 5) >= DisplayWidth) cols = wrap ();
         cols += uprintf (" NODE");
         }

      if (json_getValue (object, "isBBS", tmp, 5)
      && strcmp (tmp, "true") == 0)
         {
         if ((cols + 4) >= DisplayWidth) cols= wrap ();
         cols += uprintf (" BBS");
         }

      if (json_getValue (object, "isPMS", tmp, 5)
      && strcmp (tmp, "true") == 0)
         {
         if ((cols + 4) >= DisplayWidth) cols= wrap ();
         cols += uprintf (" PMS");
         }

      if (json_getValue (object, "isXRChat", tmp, 5)
      && strcmp (tmp, "true") == 0)
         {
         if ((cols + 7) >= DisplayWidth) cols = wrap ();
         cols += uprintf (" XRCHAT");
         }

      if (json_getValue (object, "isRTChat", tmp, 5)
      && strcmp (tmp, "true") == 0)
         {
         if ((cols + 7) >= DisplayWidth) cols = wrap ();
         cols += uprintf (" RTCHAT");
         }

      if (json_getValue (object, "isRMS", tmp, 5)
      && strcmp (tmp, "true"))
         {
         if ((cols + 4) >= DisplayWidth) cols = wrap ();
         cols += uprintf (" RMS");
         }

      if (json_getValue (object, "isDXClUS", tmp, 5)
      && strcmp (tmp, "true") == 0)
         {
         if ((cols + 7) >= DisplayWidth) cols= wrap ();
         cols += uprintf (" DXCLUS");
         }

      if (json_getValue (object, "timestamp", tmp, 40))
         {
         // There are two typs of timestamps currently in use...
         if (strchr (tmp, 'T'))  // It's ISO-8601
            {
            // 2025-10-24T12:46:52Z
            if ((cols + 21) >= DisplayWidth) cols= wrap ();
            cols += uprintf (" %s", tmp);
            }

         else  // It's Unix time
            {
            time_t   t = atoi (tmp);

            if (((unsigned)t) > 18000)
               {
               struct tm *tim = localtime (&t);
               if ((cols + 12) >= DisplayWidth) cols= wrap ();
               cols += uprintf (" %02d/%02d %02d:%02d",
                  tim->tm_mday,  tim->tm_mon+1,
                  tim->tm_hour,  tim->tm_min);
               }
            }
         }

      if (json_getValue (object, "tzMins", tmp, 8))
         {
         if (cols+3+strlen (tmp) >= DisplayWidth) cols = wrap ();
         uprintf (" tz=%s", tmp);
         }
      }
   }

/**********************************************************************/
/* Purpose:    Decode and display ARP headers
 * Called by:  process_json() for ptcl="ARP"
 * Arguments:  Pointer to string containing serialised JSON object.
 * Returns:    None
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_arp (const char *json)
   {
   char  tmp [80];

   if ((TraceFlags & TRACE_ARP) == 0) return;

   // Older software doesn't include these fields
   if (json_getValue (json, "arpOp", tmp, 79) == NULL) return;

   uprintf ("%sARP %s", Margin, tmp);

   if (json_getValue (json, "arpHwType", tmp, 79))
      uprintf (" hwtype=%s", tmp);

   if (json_getValue (json, "arpHwLen", tmp, 79))
      uprintf (" hwlen=%s", tmp);

   if (json_getValue (json, "arpPtcl", tmp, 79))
      uprintf (" prot=%s", tmp);

   if (json_getValue (json, "arpSndAddr", tmp, 79))
      uprintf ("%ssnd=%s", Margin, tmp);

   if (json_getValue (json, "arpTgtAddr", tmp, 79))
      uprintf (" tgt=%s", tmp);

   if (json_getValue (json, "arpSndHw", tmp, 79))
      uprintf (" snd_hw=%s", tmp);

   if (json_getValue (json, "arpTgtHw", tmp, 79))
      uprintf (" tgt_hw=%s", tmp);
   }

/**********************************************************************/
/* Purpose:    Decode and display IP headers
 * Called by:  process_json() for ptcl="IP"
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    Traces the main IP header fields, but not the payload
 * Affects:    stdout only
 * Returns:    None
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_ip (const char *json)
   {
   char     tmp [80], src [16], dst [16];

   if ((TraceFlags & TRACE_IP) == 0) return;

   // Older software doesn't include these fields
   if (json_getValue (json, "ipFrom", src, 15) == NULL
   || json_getValue (json, "ipTo", dst, 15) == NULL)
      return;

   // IP: 44.136.16.50 > 44.136.16.52 iplen=28 ttl=127 id=ABA0 ptcl=1 ICMP
   uprintf ("%sIP: %s > %s", Margin, src, dst);

   if (json_getValue (json, "ipLen", tmp, 6)) uprintf (" iplen=%s", tmp);

   if (json_getValue (json, "ipTTL", tmp, 3)) uprintf (" ttl=%s", tmp);

   if (json_getValue (json, "ipID", tmp, 6)) uprintf (" id=%s", tmp);

   if (json_getValue (json, "ipPtcl", tmp, 6)) uprintf (" ptcl=%s", tmp);

   if (json_getValue (json, "ipProto", tmp, 8)) uprintf (" %s", tmp);
   }

/**********************************************************************/
/* Purpose:    Decode and display NetRom routing information frames
 * Called by:  trace_netrom() only.
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    Checks the value of "l3Type", vcalling the appropriate
 *             function according to that value.
 * Returns:    None
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_netromRoutingInfo (const char *json)
   {
   char  type [16];

   if (json_getValue (json, "type", type, 15) == NULL)
      {
      if (TraceFlags & TRACE_WARNINGS)
         uprintf (" [missing 'type']");
      return;
      }

   if (strcmp (type, "NODES") == 0) trace_nodes (json);

   else if (strcmp (type, "INP3") == 0) trace_inp3 (json);

   else if (TraceFlags & TRACE_WARNINGS)
      uprintf (" [unknown 'type' '%s'", type);

   // Future types go here
   }

/**********************************************************************/
/* Purpose:    Trace a netrom routing poll
 * Called by:  x
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    x
 * Affects:    x
 * Returns:    x
 * Notes:      x
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_netromRoutingPoll (const char *json)
   {
   /// TODO: Populate me
   }

/**********************************************************************/
/* Purpose:    Decode and display NetRom layer 4 segments
 * Called by:  trace_netromL3() only
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    For l4Type "PROT_EXT" this currently displays only the
 *             protocol type (if known), else the protocol family and
 *             protocol number (if protocol not known).
 *             If l4Type is not "PROT_EXT", the frame is either a L4
 *             transport frame, or a "Netrom Record Route" frame. Both
 *             types are traced. For L4 transport, only the headers are
 *             traced, the payloads are considered sensitive.
 * Affects:    stdout only.
 * Returns:    None
 * Notes:      Tracing of NCMP, NDP, GNET etc could be added if required
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_netromL4 (const char *json)
   {
   char  tmp [2048], l4type [16];

   if ((TraceFlags & TRACE_L4) == 0) return;

   //   NetRom L4 Frame Type
   if (json_getValue (json, "l4type", l4type, 15) == 0)
      {
      if (TraceFlags & TRACE_WARNINGS)
         uprintf (" [missing l4type]\n");
      return;
      }

   if (strcmp (l4type, "unknown") == 0)
      {
      if (TraceFlags & TRACE_WARNINGS)
         uprintf (" [unknown l4type]\n");
      return;
      }

   if (strcmp (l4type, "PROT EXT") == 0)
      {
      uprintf (" <%s>", l4type);
      if (json_getValue (json, "l4Family", tmp, 80))
         uprintf (" pf=%s", tmp);
      if (json_getValue (json, "l4Proto", tmp, 80))
         uprintf (" prot=%s", tmp);
      return;
      }

   if (strcmp (l4type, "IP") == 0
   || strcmp (l4type, "NCMP") == 0
   || strcmp (l4type, "NDP") == 0
   || strcmp (l4type, "GNET") == 0)
      {
      /// TODO: Decode these properly one day
      uprintf (" <%s>", l4type);
      return;
      }

   if (strcmp (l4type, "NRR Request") == 0  // Netrom Record Route Request
   || strcmp (l4type, "NRR Reply") == 0)  // Netrom Record Route Reply
      {
      uprintf (" <%s>", l4type);

      if (json_getValue (json, "nrrId", tmp, 80))
         uprintf (" id=%s", tmp);

      if (json_getValue (json, "nrrRoute", tmp, 2047))
         uprintf ("%sRoute: %s", Margin, tmp);
      return;
      }

   if (json_getValue (json, "toCct", tmp, 8))
      uprintf (" cct=%s", tmp);

   if (strcmp (l4type, "CONN REQ") == 0
   || strcmp (l4type, "CONN_REQX") == 0)
      {
      uprintf (" <%s>", l4type);

      if (json_getValue (json, "window", tmp, 8))
         uprintf (" w=%s", tmp);

      if (json_getValue (json, "srcUser", tmp, 9))
         uprintf ("\n          %s", tmp);
      else return;

      if (json_getValue (json, "srcNode", tmp, 9))
         uprintf (" at %s", tmp);

      if (json_getValue (json, "service", tmp, 8))
         uprintf (" svc=%s", tmp);

      if (json_getValue (json, "l4t1", tmp, 8))
         uprintf (" t/o=%s", tmp);

      if (json_getValue (json, "bpqSpy", tmp, 8))
         uprintf (" bpqSpy=%s", tmp);

      return;
      }

   if (strcmp (l4type, "CONN ACK") == 0)
      {
      uprintf (" <%s>", l4type);
      if (json_getValue (json, "window", tmp, 8))
         uprintf (" w=%s", tmp);
      if (json_getValue (json, "fromCct", tmp, 8))
         uprintf (" myCct=%s", tmp);
      return; // ??
      }

   if (strcmp (l4type, "CONN NAK") == 0)
      {
      uprintf (" <%s>", l4type);
      return; // ??
      }

   if (strcmp (l4type, "DREQ") == 0
   || strcmp (l4type, "DACK") == 0)
      {
      uprintf (" <%s>", l4type);
      return;
      }

   if (strcmp (l4type, "RSET") == 0)
      {
      uprintf (" <%s>", l4type);
      if (json_getValue (json, "fromCct", tmp, 8))
         uprintf (" myCct=%s", tmp);
      return;
      }

   if (strcmp (l4type, "INFO") == 0)
      {
      uprintf (" <%s", l4type);

      if (json_getValue (json, "txSeq", tmp, 8))
         uprintf (" S%s", tmp);

      if (json_getValue (json, "rxSeq", tmp, 8))
         uprintf (" R%s", tmp);

      uprintf (">");

      if (json_getValue (json, "paylen", tmp, 8))
         uprintf (" ilen=%s", tmp);

      if (json_getValue (json, "payload", tmp, 2047))
         uprintf (":%s%s", Margin, tmp);
      }

   else if (strcmp (l4type, "INFO ACK") == 0)
      {
      uprintf (" <%s", l4type);

      if (json_getValue (json, "rxSeq", tmp, 8))
         uprintf (" R%s", tmp);

      uprintf (">");
      }

   if (json_getValue (json, "chokeFlag", tmp, 8))
         uprintf (" <CHOKE>");

   if (json_getValue (json, "nakFlag", tmp, 8))
         uprintf (" <NAK>");

   if (json_getValue (json, "moreFlag", tmp, 8))
         uprintf (" <MORE>");

   }

/**********************************************************************/
/* Purpose:    Trace L3RTT frames
 * Called by:  trace_netromL3() if l3Dest is "L3RTT"
 * Arguments:  Pointer to serialised JSON object.
 * Notes:      L3RTT is a "retrofit" to NetRom. It includes an L4 header
 *             which makes it look like an L4 INFO frame with circuit
 *             number, send and receive sequence numbers all zero. But
 *             it most definitely belongs in layer 3.
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_l3rtt (const char *json)
   {
   char  tmp [512];

   /* "l4type" should be "INFO", "toCct", "txSeq" and "rxSeq" should all
    * be 0, if you want to bother to check them
    * */

   if (json_getValue (json, "paylen", tmp, 8))
         uprintf (" ilen=%s", tmp);

   if ((TraceFlags & TRACE_L3RTT) == 0) return;

   // Payload chan be up to 236 chara, so it will wrap untidily
   /// TODO: parse the payload & present the fields in a neater form

   if (json_getValue (json, "payload", tmp, 511))
      uprintf (":%s%s", Margin, tmp);
   }


/**********************************************************************/
/* Purpose:    Display the L3 routing header, then trace layer 4
 * Called by:  trace_netrom() if l3Type is "netrom".
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    Displays the L3 source and dest calls, and TTL, then
 *             traces layer 4.
 * Affects:    stdout only
 * Returns:    None
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void trace_netromL3 (const char *json)
   {
   char tmp [16];
   bool  isL3RTT;

   if (json_getValue (json, "l3src", tmp, 10))
      uprintf ("%sNTRM: %s", Margin, tmp); // Layer 3 source

   if (json_getValue (json, "l3dst", tmp, 10))
      uprintf (" to %s", tmp);       // layer 3 dest

   isL3RTT = (strcmp (tmp, "L3RTT") == 0);

   if (json_getValue (json, "ttl", tmp, 8))
      uprintf (" ttl=%s", tmp);      // Layer 3 time to live

   if (isL3RTT) trace_l3rtt (json);
   else trace_netromL4 (json);
   }

/**********************************************************************/
/* Purpose:    Trace NetRom (PID 0xCF) frames
 * Called by:  process_json() only.
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    Calls the appropriate decoder based on l3Type
 * Affects:    stdout only
 * Returns:    None
 * Created:    24/10/2025 by Paula Dowie G8PZT.*/
/**********************************************************************/

static void trace_netrom (const char *json)
   {
   char  tmp [80];

   if ((TraceFlags & TRACE_NETROM) == 0) return;

   if (json_getValue (json, "l3Type", tmp, 79) == 0)
      {
      if (TraceFlags & TRACE_WARNINGS)
         uprintf (" [missing 'l3Type']");
      return;
      }

   if (strcmp (tmp, "NetRom") == 0) trace_netromL3 (json);

   else if (strcmp (tmp, "Routing info") == 0)
      trace_netromRoutingInfo (json);

   else if (strcmp (tmp, "Routing poll") == 0)
      trace_netromRoutingPoll (json);

   else if (TraceFlags & TRACE_WARNINGS)
      uprintf (" [unknown 'l3type': '%s'", tmp);
   }

/**********************************************************************/
/* Purpose:    Process a serialised JSON object.
 * Called by:  main() only.
 * Arguments:  Pointer to string containing serialised JSON object.
 * Actions:    Extracts values from the JSON string, applies filters,
 *             sets trace colours, traces AX25 layer2 frame and
 *             optionally into the layers above.
 * Affects:    stdout only.
 * Returns:    None
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void process_json (const char *json)
   {
   char  tmp [1024], reporter [16], portnum [16], src [16], dst [16];
   char  l2type [8], dirn [8], isRF [8], ptcl [8];

   if (json_getValue (json, "@type", tmp, 80) == 0)
      {
      if (TraceFlags & TRACE_WARNINGS)
         printf ("[missing '@type']\n");
      return;
      }

   /// TODO: Test for and process other report types here if desired
   if (strcmp (tmp, "L2Trace") != 0) return;

   // Extract some mandatory fields
   if (json_getValue (json, "reportFrom", reporter, 15) == NULL
   || json_getValue (json, "port", portnum, 15) == NULL
   || json_getValue (json, "srce", src, 15) == NULL
   || json_getValue (json, "dest", dst, 15) == NULL
   || json_getValue (json, "l2Type", l2type, 7) == NULL)
      {
      if (TraceFlags & TRACE_WARNINGS)
         printf ("[Mandatory field missing]\n");
      return;
      }

   // Extract some of the optional values.
   if (json_getValue (json, "dirn", dirn, 4) == NULL) *dirn = 0;
   if (json_getValue (json, "isRF", isRF, 4) == NULL) *isRF = 0;
   if (json_getValue (json, "ptcl", ptcl, 7) == NULL) *ptcl = 0;

   if (strcmp (l2type, "UI") == 0
   && (TraceFlags & TRACE_UI) == 0)
      return;   // UI Not wanted

   // Filter by reporting node
   if (*ReportFilter // If report filter is enabled
   && strcasecmp (reporter, ReportFilter) != 0) // and no match
      return;  // Ignore this packet

   // Filter by node's port number
   if (PortFilter && atoi (portnum) != PortFilter) return;

   // Filter by packet type
   if (*TypeFilter
   && strcasecmp (l2type, TypeFilter) != 0)
      return;

   // Filter by AX25 source call
   if (*SrcFilter
   && strcasecmp (src, SrcFilter) != 0)
      return;

   // Filter by AX25 source and destination calls
   if (*DstFilter
   && strcasecmp (dst, DstFilter) != 0)
      return;

   // Filter by either AX25 source or destination call
   if (*AllFilter
   && strcasecmp (dst, AllFilter) != 0
   && strcasecmp (src, AllFilter) != 0)
      return;

   // Filter by protocol ID
   if (*ProtoFilter
   && (*ptcl == 0 || strcasecmp (ptcl, ProtoFilter)) != 0)
      return;


   if (TraceFlags & TRACE_COLOR)
      {
      const char *colorstr;

      if (*isRF == 't') // True
         {
         switch (*dirn)
            {
            case 's':   colorstr = "\x1b[91m";   break; // red
            case 'r':   colorstr = "\x1b[92m";   break; // green
            default:    colorstr = "\x1b[93m";   break; // yellow
            }
         }

      else if (*isRF == 'f')  // False
         {
         switch (*dirn)
            {
            case 's':   colorstr = "\x1b[38;2;255;150;150m";  break;
            case 'r':   colorstr = "\x1b[38;2;50;255;150m";   break; // Cyan
            default:    colorstr = "\x1b[94m";   break; // Blue
            }
         }

      else  // Unknown RF/Inet status
         colorstr = "\x1b[0m";  // white

      /* Sending colour information to capture file allows it to be
       * played back in colour but makes it difficult to read with a
       * text editor. Therefore it is turned off by default.
       * */
      if (TraceFlags & TRACE_COLOR2FILE) uprintf ("%s", colorstr);
      else printf ("%s", colorstr);
      }

   // If raw JSON wanted, print it before the trace (defaults off)
   if (TraceFlags & TRACE_JSON) uprintf ("%s\n", json);

   // Print a blank line between traces (dedaults on)
   if (TraceFlags & TRACE_LBRK) uprintf ("\n");

   // If timestamp is wanted (defaults on)
   if (TraceFlags & TRACE_STAMP)
      {
      struct tm   *tp;
      time_t      t;

      if (json_getValue (json, "time", tmp, 20)) t = atoi (tmp);
      else t = time (NULL);

      tp = gmtime (&t);

      uprintf ("%02d:%02d:%02d ",
         tp->tm_hour, tp->tm_min, tp->tm_sec);
      }

   if (TraceFlags & TRACE_HDRLIN)
      {
      // Metadata and trace on separate lines for clarity
      uprintf ("%s port %s", reporter, portnum);
      if (*isRF) uprintf (*isRF == 't' ? " (RF)" : " (Non-RF)");
      if (*dirn) uprintf (" %s", dirn);
      uprintf (":\n  ");
      }
   else // Metadata and trace on one messy line
      {
      sprintf (tmp, "%s(%s)%c",
         reporter, portnum, *dirn ? toupper (*dirn) : ' ');

      uprintf ("%s ", tmp);
      }

   // Display L2 source, destination and type
   uprintf ("%s>%s <%s", src, dst, l2type);

   // The format of these varies with frame type...
   if (json_getValue (json, "cr", tmp, 2)) uprintf (" %s", tmp);
   if (json_getValue (json, "pf", tmp, 2)) uprintf (" %s", tmp);
   if (json_getValue (json, "rseq", tmp, 3)) uprintf (" R%s", tmp);
   if (json_getValue (json, "tseq", tmp, 3)) uprintf (" S%s", tmp);
   uprintf (">");

   // Display info field length and pid if present
   if (json_getValue (json, "ilen", tmp, 10)) uprintf (" ilen=%s", tmp);
   if (json_getValue (json, "pid", tmp, 10)) uprintf (" pid=%s", tmp);
   if (*ptcl) uprintf (" %s", ptcl);

   // Decode some payloads
   if (*ptcl)
      {
      if (strcmp (ptcl, "NET/ROM") == 0) trace_netrom (json);

      else if (strcmp (ptcl, "DATA") == 0)
         {
         // The "info" field is present only for "UI" frames
         if (json_getValue (json, "info", tmp, 1023))
            uprintf (":%s%s", Margin, tmp);

         // The "icrc" field is present only for "I" frames
         else if (json_getValue (json, "icrc", tmp, 8))
            uprintf (" CRC=%s", tmp);
         }

      else if (strcmp (ptcl, "IP") == 0) trace_ip (json);

      else if (strcmp (ptcl, "ARP") == 0) trace_arp (json);
      /// TODO: Add flexnet
      }

   uprintf ("\n");
   }

/**********************************************************************/
/* Purpose:    Display program help.
 * Called by:  main() if "-h" switch is found.
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

static void showHelp (void)
   {
   printf ("Usage: pmnptrace [options]\n\n");

   printf ("Options:\n\n"
   "   -3              Don't trace NetRom layer 3 or above\n"
   "   -4              Don't trace NetRom layer 4 or above\n"
   "   -a <callsign>   Show ALL frames to or from <callsign>\n"
   "   -c              Don't colourise the traces\n"
   "   -C              Include colour information in capture file\n"
   "   -f <callsign>   Show only frames addressed FROM <callsign>\n"
   "   -h              Show this message and exit\n"
   "   -H              Show header on separate line to trace\n"
   "   -i              Don't trace contents of INP3 routing unicasts\n"
   "   -j              Show the raw JSON before each trace\n"
   "   -k              Don't show L3RTT info field\n"
   "   -l              Suppress blank line between traces\n"
   "   -n              Don't trace contents of NetRom nodes broadcasts\n"
   "   -o <file>       Output trace to <file>\n"
   "   -p <portnum>    Show reports only from <portnum>\n"
   "   -P <protocol>   Show only frames with this L3 protocol\n"
   "   -q              No display when capturing to file (quiet)\n"
   "   -r <callsign>   Show reports only from <callsign>\n"
   "   -s              Suppress time stamp\n"
   "   -t <callsign>   Show only frames addressed TO <callsign>\n"
   "   -T <frametype>  Show only this AX25 frametype, e.g. \"-T UI\"\n"
   "   -u              Don't display UI frames\n"
   "   -w <width>      Display width (default 80 cols)\n"
   "   -W              Enable warnings of missing/bad JSON fields\n\n");
   }

/**********************************************************************/
/* Purpose:    Main function
 * Called by:  From command line
 * Arguments:  Program name, plus zero or more options
 * Actions:    Sets filters according to argument list, then loops to
 *             assemble un-named JSON objects from stdin, dispatching
 *             completed objects to the process_json() function.
 * Returns:    0 upon normal exit, else -1
 * Notes:      x
 * Created:    24/10/2025 by Paula Dowie G8PZT.
 * Modified:   */
/**********************************************************************/

int main (int argc, char *argv[])
   {
   char  buffer [4096], *cp;
   int   braceLevel = 0;
   int   c, ch, escaped = 0, inString=0;

   uprintf ("\n\"pnmptrace\" JSON to AX25 Trace Decoder for PNMP\n");
   uprintf ("Version %s, Copyright (C) 2025 G8PZT\n\n", VERSION);
   if (argc < 2) uprintf ("Use 'pnmptrace -h' to display help, "
      "Ctrl-C exits\n\n", argv [0]);

    while (1)
      {
      if ((c = getopt (argc, argv, "34a:cijklnqsuhHWf:o:p:r:t:P:T:w:")) < 0)
         break;   // End of options

      switch (c)
         {
         case 'h':   showHelp ();                        return (0);
         case 'c':   TraceFlags &= ~TRACE_COLOR;         break;
         case 'C':   TraceFlags |= TRACE_COLOR2FILE;     break;
         case 'u':   TraceFlags &= ~TRACE_UI;            break;
         case 'i':   TraceFlags &= ~TRACE_INP3;          break;
         case 'n':   TraceFlags &= ~TRACE_NODES;         break;
         case '3':   TraceFlags &= ~TRACE_NETROM;        break;
         case '4':   TraceFlags &= ~TRACE_L4;            break;
         case 's':   TraceFlags &= ~TRACE_STAMP;         break;
         case 'k':   TraceFlags &= ~TRACE_L3RTT;         break;
         case 'l':   TraceFlags &= ~TRACE_LBRK;          break;
         case 'j':   TraceFlags |= TRACE_JSON;           break;
         case 'H':   TraceFlags |= TRACE_HDRLIN;         break;
         case 'a':   strncpy (AllFilter, optarg, 15);    break;
         case 'f':   strncpy (SrcFilter, optarg, 15);    break;
         case 't':   strncpy (DstFilter, optarg, 15);    break;
         case 'T':   strncpy (TypeFilter, optarg, 15);   break;
         case 'r':   strncpy (ReportFilter, optarg, 15); break;
         case 'o':   strncpy (CaptureFile, optarg, 255); break;
         case 'p':   PortFilter = atoi (optarg);         break;
         case 'P':   strncpy (ProtoFilter, optarg, 15);  break;
         case 'q':   TraceFlags |= TRACE_QUIET;          break;
         case 'w':   DisplayWidth = atoi (optarg);       break;
         case 'W':   TraceFlags |= TRACE_WARNINGS;       break;
         }
      }

   if (*CaptureFile)
      {
      if ((FpCapture = fopen (CaptureFile, "w")) == NULL)
         {
         printf ("Can't open capture file '%s'\n", CaptureFile);
         return (-1);
         }
      printf ("Capturing traces to file '%s'\n", CaptureFile);
      }

   if (*ReportFilter)
      uprintf ("Showing reports from node '%s' only\n", ReportFilter);

   if (PortFilter)
      uprintf ("Showing frames to/from port (%d) only\n",
         PortFilter);

   if (*SrcFilter)
      uprintf ("Showing frames with L2 source call '%s' only\n",
         SrcFilter);

   if (*DstFilter)
      uprintf ("Showing frames with L2 destination call '%s' only\n",
         DstFilter);

   if (*AllFilter)
      uprintf ("Showing frames to/from L2 call '%s' only\n", AllFilter);

   if (*TypeFilter)
      uprintf ("Showing '%s' frames only\n", TypeFilter);

   if (*ProtoFilter)
      uprintf ("Showing frames with L3 protocol '%s' only\n",
         ProtoFilter);

   if ((TraceFlags & TRACE_UI) == 0) uprintf ("Not showing UI frames\n");

   if ((TraceFlags & TRACE_NETROM) == 0)
      uprintf ("Not decoding NODES broadcasts\n");

   if ((TraceFlags & TRACE_INP3) == 0)
      uprintf ("Not decoding INP3 unicasts\n");

   if ((TraceFlags & TRACE_NETROM) == 0)
      uprintf ("Not decoding NetRom Layer 3 or above\n");

   if ((TraceFlags & TRACE_L4) == 0)
      uprintf ("Not decoding NetRom Layer 4 or above\n");

   if ((TraceFlags & TRACE_L3RTT) == 0)
      uprintf ("Not showing L3RTT frame contents\n");

   if (TraceFlags & TRACE_JSON) uprintf ("Including JSON data\n");

   if ((TraceFlags & TRACE_STAMP) == 0)
      uprintf ("Time stamp disabled\n");

   cp = buffer;

   while (1)   // Forever loop
      {
      // Get a char from stdin - blocking
      if ((ch = getchar ()) == EOF) break;

      if (braceLevel == 0) // Waiting for opening brace
         {
         if (ch == '{')    // Found the opening brace
            {
            braceLevel = 1;
            cp = buffer;   // Point cp at start of object buffer
            }
         continue;
         }

      // If we get here, braceLevel is > 0

      if (ch == '}')       // Possible end of object
         {
         if (!escaped            // If not in "escaped" mode,
         && !inString            // and not within a string,
         && --braceLevel == 0)   // and it is the final brace
            {
            *cp++ = 0;              // Terminate the string
            process_json (buffer);  // Process the object
            cp = buffer;            // Reset the pointer
            continue;
            }
         }

      *cp++ = ch;     // Copy the character to the object buffer

      if (ch == '{'     // Possible start of object within object
      && !escaped && !inString)
         {
         braceLevel++;
         continue;
         }

      if (escaped)
         {
         escaped = 0;
         continue;
         }
      else  // Not in escaped mode
         {
         if (ch == '\\')   // If it's the escape character
            {
            escaped = 1;   // Set escaped mode
            continue;
            }
         }

      // Not escape and not '\'

      if (ch == '"') // Start of end of string
         {
         if (inString) inString = 0;
         else inString = 1;
         continue;
         }

      }  // end of while()

   if (FpCapture) fclose (FpCapture);

   return (0);
   }
