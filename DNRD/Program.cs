// See https://aka.ms/new-console-template for more information

using System.Net;
using DNRD.Utils;

namespace DNRD;

public static class RoutingTables
{
    public const int MasterIpv4 = -1;
    public const int MasterIpv6 = -2;
    
    public static readonly RoutingLookup.Ipv4 MasterIpv4Routes = new RoutingLookup.Ipv4();

    public static readonly Dictionary<string, int> VrfIndex = new Dictionary<string, int>();
    public static readonly List<Vrf> VrfTable = new List<Vrf>();
}

public static partial class Routes
{
    public unsafe struct Ipv4Route
    {
        public fixed byte DestinationSubnet[4];
        public byte CidrMask;
        public fixed byte NextHop[4];
        public uint Metric;
    }
    
    public unsafe struct Ipv6Route
    {
        public fixed byte DestinationSubnet[16];
        public byte CidrMask;
        public fixed byte NextHop[16];
        public uint Metric;
    }
}

public class Vrf
{
    public Vrf(string vrfName)
    {
        RoutingTables.VrfIndex[vrfName] = RoutingTables.VrfTable.Count;
    }
    
    public List<Routes.Ipv4Route> Ipv4Routes = new List<Routes.Ipv4Route>();
    public List<Routes.Ipv6Route> Ipv6Routes = new List<Routes.Ipv6Route>();
}

public static class Program
{
    public static void Main(string[] args)
    {
        
        /*Bgp.RouterIdentifier = new byte[] { 192, 168, 74, 101 };
        var requiredCapabilities = new List<byte> {Bgp.Capability.FourOctetAs, Bgp.Capability.RouteRefresh};

        Bgp.AddNeighbour(new Bgp.BgpNeighbour()
        {
            NeighbourIp = IPAddress.Parse("192.168.74.34"),
            AsNumber = 100,
            NeighbourAs = 666,
            HoldTime = 240,
            RequiredCapabilities = requiredCapabilities,
            SupportedFamilys = { Bgp.Ipv4Unicast },
            ImportTables = { RoutingTables.MasterIpv4 }
        });
        

        var bgpRouter = new Thread(Bgp.Start);
        //bgpRouter.Start();
        */
        
        var exampleRoute = new RoutingLookup.Ipv4.Ipv4Route(0x00000001, 100);
        var exampleRoute2 = new RoutingLookup.Ipv4.Ipv4Route(0x00000002, 100);
        var ipv4Table = new RoutingLookup.Ipv4();
        
        ipv4Table.AddRoute(0xfffffffc, 30, exampleRoute2);
        ipv4Table.AddRoute(0x10000000, 15, exampleRoute2);
        ipv4Table.AddRoute(0xfffffff0, 28, exampleRoute2);
        //Console.WriteLine(ipv4Table.ToSafeIpv4Node().ChildrenBitmap);

        foreach (var (subnet, cidr, route) in ipv4Table)
        {
            Console.WriteLine($"{Convert.ToString(subnet, 16)}/{cidr} -> {route.NextHop}");
        }
        
        Console.WriteLine(ipv4Table.LookupRoute(0xffffffff).NextHop);
    }
}
