using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace DNRD;

public static partial class Routes
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void CidrToMask_Ipv4(byte cidr, Span<byte> mask)
    {
        
        /*
         * Optimized CIDR number to Subnet Mask Converter
         * Example: converting a /17 to 255.255.128.0
         * 
         * Step 1. Initialise a number with the following format (33 bits)
         * 11111111 11111111 11111111 11111111
         *
         * Step 2. Bitshift the amount of cidr bits right, in this case 17
         * 00000000 00000000 01111111 11111111
         *
         * Step 3. Bitflip the integer
         * 11111111 11111111 10000000 00000000
         *
         * Step 4. Take the pointer of the integer and put the bytes into the
         * span taking endianness into consideration
         */

        var integerMask = ~(0xffffffff >> cidr);
        var pointer = (byte*)&integerMask;
        if (BitConverter.IsLittleEndian)
        {
            mask[0] = pointer[3];
            mask[3] = pointer[0];
            mask[1] = pointer[2];
            mask[2] = pointer[1];
        }
        else
        {
            mask[3] = pointer[3];
            mask[2] = pointer[2];
            mask[1] = pointer[1];
            mask[0] = pointer[0];
        }
    }
}

public static partial class Bgp
{
    public record struct AddressFamily(int Afi, byte Safi)
    {
        public readonly int Afi = 0;
        public readonly byte Safi = 0;
    }

    public static AddressFamily Ipv4Unicast = new AddressFamily(1, 1);
    
    public static class NetUtils
    {
        public static void ReceiveBytes(in Socket handler, Span<byte> buffer)
        {
            var receivedLength = 0;
            var length = buffer.Length;
            while (receivedLength < length)
            {
                receivedLength += handler.Receive(buffer.Slice(receivedLength, length-receivedLength));
                // TODO : Implement BGP ticks
            }
        }
    }
    
    public enum State : byte 
    { 
        Idle,
        Connect,
        OpenSent,
        OpenConfirm,
        Established
    }

    public static partial class Capability
    {
        public const byte RouteRefresh = 2;
        public const byte ExtendedMessage = 6;
        public const byte EnchancedRouteRefresh = 70;
        public const byte LongLivedGracefulRestart = 71;
        public const byte GracefulRestart = 64;
        public const byte FourOctetAs = 65;
        public const byte Fqdn = 73;
        public const byte MpBgp = 1;
    }

    public static partial class Message
    {
        public const byte Open = 1;
        public const byte Update = 2;
        public const byte Notification = 3;
        public const byte Keepalive = 4;
        public const byte RouteRefresh = 5;
    }

    public static class OpenParameter
    {
        public const byte CapabilitiesParameter = 2;
        public const byte ExtendedParams = 255;
    }
    
    public static class Notifications 
    { 
    
        // Error codes
        public const byte MessageHeaderError = 1;
        public const byte OpenMessageError = 2;
        public const byte UpdateMessageError = 3;
        public const byte HoldTimerError = 4;
        public const byte FsmError = 5;
        public const byte Cease = 6;

        // Message header subcodes
        public const byte ConnectionNotSynchronized = 1;
        public const byte BadMessageLength = 2;
        public const byte BadMessageType = 3;

        // Open message subcodes

        public const byte UnsupportedVersionNumber = 1;
        public const byte BadPeerAs = 2;
        public const byte BadBgpIdentifier = 3;
        public const byte UnsupportedOptionalParameter = 4;
        public const byte UnacceptableHoldTime = 6;
        public const byte UnsupportedCapability = 7;

        // Update message subcodes
        public const byte MalformedAttributeList = 1;
        public const byte UnrecognizedWellknownAttribute = 2;
        public const byte MissingWellknownAttribute = 3;
        public const byte AttributeFlagsError = 4;
        public const byte AttributeLengthError = 5;
        public const byte InvalidOriginAttribute = 6;
        public const byte InvalidNextHopAttribute = 8;
        public const byte OptionalAttributeError = 9;
        public const byte InvalidNetworkField = 10;
        public const byte MalformedAsPath = 11;

    }

    // Use one multiconnection thread (bookmarked) to handle all but start with a reachout using  a new thread and then check neighbour info to run
    public static readonly byte[] MessageMarker = new byte[] { 
                                                               255, 255, 255, 255, 255, 255, 255, 255,
                                                               255, 255, 255, 255, 255, 255, 255, 255
                                                              };

    public static readonly byte[] BgpVersion = new byte[] { 4, 0 };
    
    public static uint? AsNumber;
    public static byte[]? RouterIdentifier = new byte[] { 0, 0, 0, 0 };
    
    public record BgpNeighbour 
    {
        public State State = State.Idle;
        public long KeepAliveTimer;
        public uint NeighbourAs;
        public uint HoldTime;
        public uint Llst = 0;
        public ushort RestartApprox = 0;
        
        public uint AsNumber;
        public IPAddress? NeighbourIp;
        public readonly byte[] NeighbourRouterId = new byte[4];

        public bool FourOctetAs = true;
        public bool GracefulRestart = true;
        public bool RouteRefresh = true;
        public bool Extended = true;
        public bool EnhancedRouteRefresh = false;
        public bool Llgr = false;
        public bool Fqdn = false;
        public List<byte> RequiredCapabilities = null!;

        public bool NFourOctetAs = false;
        public bool NGracefulRestart = false;
        public bool NRouteRefresh = false;
        public bool NEnhancedRouteRefresh = false;
        public bool NLlgr = false;
        public bool NFqdn = false;
        public bool NExtended = false;
        public bool NMpBgp = false;
        
        public bool Restarting;
        public bool Preserved;

        public List<int> ImportTables = null!;

        public readonly HashSet<AddressFamily> SupportedFamilys = new HashSet<AddressFamily>();
        public readonly HashSet<AddressFamily> ConnectionFamilys = new HashSet<AddressFamily>();   
        
        //public List<byte>? AdjCapabilites;
    }
}