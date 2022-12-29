using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;

namespace DNRD;

// In Protocols/Utils.cs
public static partial class Bgp
{
    public static class Ipv4
    {
        public struct BgpEntry
        {
            public BgpRoute Route;
            public ushort Metric;
            public ushort LocalPreference;
            public byte Origin;
            public long Age;
        }
        
        public unsafe struct BgpRoute
        {
            public fixed byte DestinationSubnet[4];
            public byte CidrMask;
            public fixed byte NextHop[4];
            public fixed byte NeighbourRouterId[4];
            public List<uint> AsPath;
        }
        
        public static volatile List<BgpEntry> AdjRibIn = new List<BgpEntry>();
        public static volatile List<BgpEntry> LocalRib = new List<BgpEntry>();
        public static volatile List<BgpEntry> AdjRibOut = new List<BgpEntry>();
    }
    
    public static volatile Dictionary<IPAddress, int> NeighboursIndex = new Dictionary<IPAddress, int>();
    public static volatile List<byte> Capabilities = new List<byte>();
    public static volatile List<BgpNeighbour> Neighbours = new List<BgpNeighbour>();
    public static bool Running = false;

    public static partial class Capability
    {
        public static bool HandleCapability(in Socket handler, Span<byte> buffer, int neighbourIndex, int length)
        {
            var offset = 0;
            var capHeader = buffer[..length];

            Span<byte> unsupportedCapabilities = stackalloc byte[256];
            var unsupportedOffset = 0;

            while (offset < length)
            {
                var capLength = capHeader[1];
                var capValue = capHeader.Slice(2, capLength);
                var capType = capHeader[0];
                offset += capLength + 2;
                capHeader = buffer.Slice(offset, length-offset);

                switch (capType)
                {
                    case ExtendedMessage:
                        Neighbours[neighbourIndex].NExtended = true;
                        break;
                    case RouteRefresh:
                        Neighbours[neighbourIndex].NRouteRefresh = true;
                        break;
                    case GracefulRestart:
                        Neighbours[neighbourIndex].NGracefulRestart = true;
                        break;
                    case EnchancedRouteRefresh:
                        Neighbours[neighbourIndex].NEnhancedRouteRefresh = true;
                        break;
                    case LongLivedGracefulRestart:
                        Neighbours[neighbourIndex].NLlgr = true;
                        break;
                    case FourOctetAs:
                        Neighbours[neighbourIndex].NFourOctetAs = true;
                        uint asNumber = capValue[3];
                        asNumber += (uint)(capValue[2] << 8);
                        asNumber += (uint)(capValue[1] << 16);
                        asNumber += (uint)(capValue[0] << 24);


                        if (asNumber != Neighbours[neighbourIndex].NeighbourAs)
                        {
                            Message.SendNotification(handler, Notifications.Cease, 0, Span<byte>.Empty, unsupportedCapabilities);
                            return false;
                        }
                        break;
                    case Capability.MpBgp:
                        Neighbours[neighbourIndex].NMpBgp = true;
                        var afi = (capValue[0] << 8) + capValue[1];
                        var safi = capValue[3];
                        var family = new AddressFamily(afi, safi);

                        if (!Neighbours[neighbourIndex].SupportedFamilys.Contains(family))
                        {
                            capHeader[..(capLength+2)].CopyTo(unsupportedCapabilities.Slice(unsupportedOffset, capLength+2));
                            unsupportedOffset += capLength + 2;
                        }

                        Neighbours[neighbourIndex].ConnectionFamilys.Add(family);
                        break;
                    case Capability.Fqdn:
                        break;
                    default:
                        capHeader[..(capLength+2)].CopyTo(unsupportedCapabilities.Slice(unsupportedOffset, capLength+2));
                        unsupportedOffset += capLength + 2;
                        break;
                }

            }

            if (unsupportedOffset <= 0) return true;
            
            Span<byte> tmpBuffer = stackalloc byte[288]; 
            Message.SendNotification(handler, Notifications.OpenMessageError, Notifications.UnsupportedCapability, unsupportedCapabilities, tmpBuffer);
            return false;
        }
    }
    
    public static partial class Message
    {
        public static bool HandleOpen(in Socket handler, Span<byte> buffer, int neighbourIndex, int length)
        {
            byte[]? rented = null;
            var openMessage = length > 512 ? (rented = ArrayPool<byte>.Shared.Rent(length))[..length] : buffer[..length];
            try
            {
                NetUtils.ReceiveBytes(handler, openMessage);
            
                var openHeader = openMessage[..10];
                var optionalParamsLength = openHeader[9];
                Console.WriteLine(optionalParamsLength);
                openHeader.Slice(5, 4).CopyTo(Neighbours[neighbourIndex].NeighbourRouterId.AsSpan());

                var holdTime = (ushort)((openHeader[3] << 8) + openHeader[4]);

                Neighbours[neighbourIndex].HoldTime = holdTime;
            
                var neighbourAs = (ushort)((openHeader[1] << 8) + openHeader[2]);
                var bgpVersion = openHeader[0];
                if (bgpVersion < 4)
                {
                    Console.WriteLine("Version");
                    SendNotification(handler, Notifications.Cease, 0, Span<byte>.Empty, buffer);
                    if (rented != null) { ArrayPool<byte>.Shared.Return(rented, clearArray: false); }
                    return false;
                }
                
                var paramsBuffer = openMessage.Slice(10, optionalParamsLength);
                
                var offset = 0;
                while (offset < optionalParamsLength)
                {
                    var paramLength = paramsBuffer[offset+1];
                    var paramType = paramsBuffer[offset];
                    var paramValue = paramsBuffer.Slice(offset+2, paramLength);
                    offset += paramLength + 2;

                    switch (paramType)
                    {
                        case OpenParameter.CapabilitiesParameter:
                            if (!Capability.HandleCapability(handler, paramValue, neighbourIndex, paramLength))
                            {
                                Console.WriteLine("Capability");
                                SendNotification(handler, Notifications.Cease, 0, Span<byte>.Empty, buffer);
                                if (rented != null) { ArrayPool<byte>.Shared.Return(rented, clearArray: false); }
                                return false;
                            }
                            break;
                        case OpenParameter.ExtendedParams:
                            // TODO: Implement Extended Params (Pain in the ass)
                            break;
                        default:
                            SendNotification(handler, Notifications.OpenMessageError, Notifications.UnsupportedOptionalParameter, Span<byte>.Empty, buffer);
                            if (rented != null) { ArrayPool<byte>.Shared.Return(rented, clearArray: false); }
                            return false;
                    }
                }
                
                
                if (neighbourAs != Neighbours[neighbourIndex].NeighbourAs && !Neighbours[neighbourIndex].FourOctetAs)
                {
                    SendNotification(handler, Notifications.Cease, 0, Span<byte>.Empty, buffer);
                    if (rented != null) { ArrayPool<byte>.Shared.Return(rented, clearArray: false); }
                    return false;
                }


            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
            
            if (rented != null) { ArrayPool<byte>.Shared.Return(rented, clearArray: false); }
            

            return true;

        }

        public static void HandleUpdate(in Socket handler, Span<byte> buffer, int neighbourIndex)
        {
            
        }

        public static void HandleNotification(in Socket handler, Span<byte> buffer, int neighbourIndex, int length)
        {
            byte[]? rented = null;
            var notificationMessage = length > 512 ? (rented = ArrayPool<byte>.Shared.Rent(length)).AsSpan()[..length] : buffer[..length];

            try
            {
                var code = notificationMessage[0];
                var subcode = notificationMessage[1];
                var value = notificationMessage.Slice(2, length - 2);

                switch (code)
                {
                    case Notifications.OpenMessageError:
                        switch (subcode)
                        {
                            case Notifications.UnsupportedCapability:
                                if (value.Length < 2) break;
                                var offset = 0;
                                while (offset < value.Length)
                                {
                                    offset = offset + 2 + value[offset + 1];
                                    
                                    var capability = value[offset];
                                    if (!Neighbours[neighbourIndex].RequiredCapabilities.Contains(capability))
                                    {
                                        switch (capability)
                                        {
                                            case Capability.ExtendedMessage:
                                                Neighbours[neighbourIndex].Extended = false;
                                                break;
                                            case Capability.RouteRefresh:
                                                Neighbours[neighbourIndex].RouteRefresh = false;
                                                break;
                                            case Capability.GracefulRestart:
                                                Neighbours[neighbourIndex].GracefulRestart = false;
                                                break;
                                            case Capability.EnchancedRouteRefresh:
                                                Neighbours[neighbourIndex].EnhancedRouteRefresh = false;
                                                break;
                                            case Capability.LongLivedGracefulRestart:
                                                Neighbours[neighbourIndex].Llgr = false;
                                                break;
                                            case Capability.FourOctetAs:
                                                Neighbours[neighbourIndex].FourOctetAs = false;
                                                break;
                                            case Capability.Fqdn:
                                                Neighbours[neighbourIndex].Fqdn = false;
                                                break;
                                        }
                                    }
                                }


                                break;
                        }

                        break;
                }
                
            }
            finally
            {
                if (rented != null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }

        public static void HandleRouteRefresh(in Socket handler, Span<byte> buffer, int neighbourIndex) {}

        public static void SendOpen(in Socket handler, Span<byte> buffer, int neighbourIndex)
        {
            MessageMarker.CopyTo(buffer[..16]);
            
            // Avoid bounds checking on all below variables by indexing above them so the compiler gets the hint
            buffer[511] = 0;
            buffer[18] = 1;
            buffer[19] = 4;

            var holdTime = Neighbours[neighbourIndex].HoldTime;
            buffer[21] = (byte) (Neighbours[neighbourIndex].AsNumber & 0xff);
            buffer[20] = (byte) (Neighbours[neighbourIndex].AsNumber - buffer[21]);;
            buffer[22] = 0;
            buffer[24] = (byte)(holdTime % 256);
            buffer[23] = (byte)(holdTime-buffer[24]);
            RouterIdentifier.CopyTo(buffer.Slice(24, 4));

            buffer[29] = 2;

            var offset = 31;
            var paramBuffer = buffer.Slice(31, 256);

            if (Neighbours[neighbourIndex].RouteRefresh)
            {
                paramBuffer[0] = Capability.RouteRefresh;
                paramBuffer[1] = 0;
                
                offset += 2;
                paramBuffer = buffer.Slice(offset, 256);
            }
            
            if (Neighbours[neighbourIndex].GracefulRestart)
            {
                var time = Neighbours[neighbourIndex].RestartApprox;
                paramBuffer[0] = Capability.GracefulRestart;
                paramBuffer[1] = 2;
                
                paramBuffer[2] = (byte) (0x80 | ((time >> 8) & 0x0f));
                paramBuffer[3] = (byte) (time & 0xff);
                offset += 4;
                paramBuffer = buffer.Slice(offset, 256);
            }
            
            if (Neighbours[neighbourIndex].FourOctetAs)
            {
                var asNumber = Neighbours[neighbourIndex].AsNumber;
                paramBuffer[5] = (byte)(asNumber & 0xff);
                paramBuffer[4] = (byte)((asNumber >> 8) & 0xff);
                paramBuffer[3] = (byte)((asNumber >> 16) & 0xff);
                paramBuffer[2] = (byte)((asNumber >> 24) & 0xff);
                
                paramBuffer[0] = Capability.FourOctetAs;
                paramBuffer[1] = 4;
                
                offset += 6;
                paramBuffer = buffer.Slice(offset, 256);
            }
            
            if (Neighbours[neighbourIndex].EnhancedRouteRefresh)
            {
                paramBuffer[0] = Capability.EnchancedRouteRefresh;
                paramBuffer[1] = 0;
                
                offset += 2;
                paramBuffer = buffer.Slice(offset, 256);
            }
            
            if (Neighbours[neighbourIndex].Llgr)
            {
                paramBuffer[0] = Capability.LongLivedGracefulRestart;
                paramBuffer[1] = 0;
                
                offset += 2;
                paramBuffer = buffer.Slice(offset, 256);
            }
            
            if (Neighbours[neighbourIndex].Extended)
            {
                paramBuffer[0] = Capability.ExtendedMessage;
                paramBuffer[1] = 0;
                
                offset += 2;
                paramBuffer = buffer.Slice(offset, 256);
            }

            foreach (var family in Neighbours[neighbourIndex].SupportedFamilys)
            {
                paramBuffer[5] = family.Safi;
                paramBuffer[4] = 0;
                paramBuffer[3] = (byte)(family.Afi & 0xff);
                paramBuffer[2] = (byte)((family.Afi - paramBuffer[3]) & 0xffff);

                paramBuffer[0] = Capability.MpBgp;
                paramBuffer[1] = 4;

                offset += 6;
            }

            if (offset > 31)
            {
                buffer[30] = (byte)(offset - 31);
                buffer[28] = (byte)(offset - 29);
            }
            else
            {
                offset -= 2;
            }
            buffer[17] = (byte)(offset % 256);
            buffer[16] = (byte)(offset >> 8);
            handler.Send(buffer[..offset]);

        }
        
        public static void SendNotification(in Socket handler, byte errorCode, byte subcode, Span<byte> data, Span<byte> buffer)
        {
            var dataLength = data.Length;
            byte[]? rented = null;
        
            Span<byte> sendBuffer = 
                21 + dataLength > 512 
                    ? (rented = ArrayPool<byte>.Shared.Rent(21 + dataLength))
                    : buffer;
        
            MessageMarker.CopyTo(sendBuffer[..16]);
            sendBuffer[20] = subcode;
            sendBuffer[19] = errorCode;
            
            sendBuffer[18] = 3;
            sendBuffer[17] = (byte)((dataLength + 21) % 256);
            sendBuffer[16] = (byte)((dataLength + 21) - sendBuffer[17]);

            data.CopyTo(sendBuffer.Slice(21,dataLength));

            try
            {
                handler.Send(sendBuffer[..(21+dataLength)]);
            }
            finally
            {
                if (rented != null)
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
        }

        public static void SendKeepAlive(in Socket handler, Span<byte> buffer)
        {
            MessageMarker.CopyTo(buffer[..16]);
            buffer[17] = 19;
            buffer[16] = 0;
            buffer[18] = 4;

            handler.Send(buffer[..19]);
        }
    }
    
    public static void Start()
    {
        // Start outgoing connections
        foreach (var neighbour in Neighbours)
        {
            var neighbourOutgoing = new Thread(()=>OutgoingConnection(neighbour));
            neighbourOutgoing.Start();
        }
        
        // Start listening for incoming connections
        var listener = new TcpListener(IPAddress.Parse("0.0.0.0"), 179);
        
        listener.Start();
        Running = true;
        
        while (Running) 
        {
            var handler = listener.AcceptSocket();
            var endpoint = (handler.RemoteEndPoint as IPEndPoint)!;
            var neighbourListener = new Thread(()=>BgpConnection(handler, NeighboursIndex[endpoint.Address]));
            neighbourListener.Start();
        }
    }

    private static void OutgoingConnection(BgpNeighbour neighbour)
    {
        var neighbourIpString = neighbour.NeighbourIp!.ToString();
        
        try
        {
            using var handler = new TcpClient(neighbourIpString, 179);

            var neighbourIndex = NeighboursIndex[neighbour.NeighbourIp!];
            while (Running)
            {
                BgpConnection(handler.Client, neighbourIndex);
                Neighbours[neighbourIndex].State = State.Idle;
                Thread.Sleep(400);
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"% BGP : Connection dead -= {neighbourIpString}:179");
        }
        
    }

    [SkipLocalsInit]
    private static void BgpConnection(in Socket handler, int neighbourIndex)
    {
        if (Neighbours[neighbourIndex].State > State.Idle) return;
        Neighbours[neighbourIndex].State = State.Connect;

        /* Buffer allocation for BGP Connection
         *
         * All headers should be recieved using the buffer span
         * This Span is stackalloced due to the potential cache improvement
         *
         * This should be used for all TLV and message headers
         * the only place where this may not be used is an UPDATE message
         * where NRLI and Withdrawn routes above the length of 512 bytes should use ArrayPool<byte>.Shared
         */
        
        Span<byte> buffer = stackalloc byte[512];

        Message.SendOpen(handler, buffer, neighbourIndex);
        Neighbours[neighbourIndex].State = State.OpenSent;
        handler.ReceiveTimeout = 500;
        while (Running)
        {
            var messageHeader = buffer[..19];
            NetUtils.ReceiveBytes(handler, messageHeader);
            
            var type = messageHeader[18];
            var length = (ushort)(messageHeader[16] << 8) + messageHeader[17];
            
            if (messageHeader[..16] == MessageMarker.AsSpan())
            {
                Message.SendNotification(handler, Notifications.MessageHeaderError, Notifications.ConnectionNotSynchronized, Span<byte>.Empty, buffer);
                break;
            }

            switch (type)
            {
                case Message.Open:
                    if (length is < 29 or > 4096)
                    {
                        Message.SendNotification(handler, Notifications.MessageHeaderError, Notifications.BadMessageLength, Span<byte>.Empty, buffer);
                        return;
                    }

                    if (!Message.HandleOpen(handler, buffer, neighbourIndex, length - 19)) return;

                    if (Neighbours[neighbourIndex].State > State.OpenConfirm)
                    {
                        return;
                    }
                    Neighbours[neighbourIndex].State = State.OpenConfirm;
                    Message.SendKeepAlive(handler, buffer);
                    // TODO: Dump routing table
                    break;
                case Message.Update:
                    Message.HandleUpdate(handler, buffer, neighbourIndex);
                    NetUtils.ReceiveBytes(handler, buffer[..(length-19)]);
                    break;
                case Message.Notification:
                    Message.HandleNotification(handler, buffer, neighbourIndex, length-19);
                    Neighbours[neighbourIndex].State = State.Idle;
                    return;
                case Message.Keepalive:
                    if (Neighbours[neighbourIndex].State == State.OpenConfirm)
                        Neighbours[neighbourIndex].State = State.Established;

                    if (Neighbours[neighbourIndex].State < State.OpenConfirm)
                    {
                        Message.SendNotification(handler, Notifications.Cease, 0, Span<byte>.Empty, buffer);
                        return;
                    }
                    
                    break; 
                case Message.RouteRefresh:
                    Message.HandleRouteRefresh(handler, buffer, neighbourIndex);
                    NetUtils.ReceiveBytes(handler, buffer[..(length-19)]);
                    break;
                default:
                    Message.SendNotification(handler, Notifications.MessageHeaderError, Notifications.BadMessageType, Span<byte>.Empty, buffer);
                    return;
            }
        }
    }
    
    public static void AddNeighbour(BgpNeighbour neighbour)
    {
        Neighbours.Add(neighbour);
        NeighboursIndex[neighbour.NeighbourIp!] = Neighbours.IndexOf(neighbour);

        if (!Running) return;
        var neighbourOutgoing = new Thread(()=>OutgoingConnection(neighbour));
        neighbourOutgoing.Start();
    }

}