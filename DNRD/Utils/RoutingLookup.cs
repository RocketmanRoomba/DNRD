using System.Collections;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace DNRD.Utils;

public static class RoutingLookup
{
    // These 2 classes are the same but with different route information
    // Cannot use inheritence due to the unsafe nature and need for speed
    
    public sealed class BgpIpv4 : IEnumerable<(uint, byte, BgpIpv4.BgpRoute)>, IDisposable
    {
        public unsafe BgpIpv4()
        {
            for (var i = 0; i < 2; i++) _treeLookup[0b01_000 + (i<<2)] = (byte) (i+1);
            for (var c = 0; c < 4; c++) _treeLookup[0b10_000 + (c<<1)] = (byte) (c+3);
            for (var z = 0; z < 8; z++) _treeLookup[0b11_000 + z] = (byte) (z + 7);

            _oRootNode =  (Node*) Marshal.AllocHGlobal(IntPtr.Size * 2 + 3).ToPointer();
            Unsafe.InitBlockUnaligned(_oRootNode, 0, (uint) ChildrenSize);
        }

        ~BgpIpv4()
        {
            Dispose();
        }

        public unsafe void Dispose()
        {
            GC.SuppressFinalize(this);
            DeleteChildrenRecursive(_oRootNode);
            Marshal.FreeHGlobal((IntPtr)_oRootNode);

            _oRootNode = (Node*) 0;
        }
        
        public readonly struct BgpRoute
        {
            public readonly uint NextHop;
            public readonly ushort Metric;
            public readonly ushort LocalPreference;
            public readonly ushort AsPathLength;
            public readonly unsafe ushort* AsPath;
            public readonly ushort CommunitiesLength;
            public readonly unsafe ushort* Communities;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public unsafe struct Node
        {
            public Node* Children;
            public BgpRoute* Prefixs;
            public byte ChildrenBitmap;
            public ushort PrefixBitmap;
        }
        
        private readonly byte[] _treeLookup = new byte[64];
        private unsafe Node* _oRootNode;
        private const byte RootNode4 =  11;
        private static readonly unsafe int ChildrenSize = sizeof(Node);
        private static readonly unsafe int PrefixSize = sizeof(BgpRoute);
        
        private static unsafe void DeleteChildrenRecursive(Node* node)
        {
            Node* children = node->Children;
            
            if (node->PrefixBitmap != 0) Marshal.FreeHGlobal((IntPtr)node->Prefixs);
            if (node->ChildrenBitmap == 0) return;
            
            for (var i = 0; i < 8; i++)
            {
                if (((128 >> i) & node->ChildrenBitmap) != 0) DeleteChildrenRecursive(children + i);
            }
            
            Marshal.FreeHGlobal((IntPtr)node->Children);
        }
        
        private static unsafe bool CollectDeadBranches(Node* node)
        {
            Node* children = node->Children;

            var dead = true;
            for (var i = 0; i < 8; i++)
            {
                if (((128 >> i) & node->ChildrenBitmap) == 0) continue;
                if (!CollectDeadBranches(children + i)) dead = false;
            } 
            
            if (node->PrefixBitmap != 0) dead = false;

            if (dead && node->ChildrenBitmap != 0) Marshal.FreeHGlobal((IntPtr)node->Children);
            if (dead && node->PrefixBitmap != 0) Marshal.FreeHGlobal((IntPtr)node->Prefixs);
            
            return dead;
        }
        
        public unsafe bool CleanupDeadEntries() => CollectDeadBranches(_oRootNode);
        
        public unsafe void ClearAllEntries()
        {
            _oRootNode->ChildrenBitmap = 0;
            _oRootNode->PrefixBitmap = 0;
            DeleteChildrenRecursive(_oRootNode);
        }
        
        public class SafeIpv4Node
        {
            private readonly unsafe Node* _node;
            public unsafe SafeIpv4Node(Node* ptr) => _node = ptr;
            public unsafe SafeIpv4Node Children(int child) => new(_node->Children + child);
            public unsafe BgpRoute Prefix(int prefix) => *(_node->Prefixs + prefix);
            public unsafe byte ChildrenBitmap => _node->ChildrenBitmap;
            public unsafe ushort PrefixBitmap => _node->PrefixBitmap;
        }
        
        private static IEnumerable<(uint, byte, BgpRoute)> EnumerateNode(SafeIpv4Node node, byte level, uint prefixReconstruct)
        {

            for (var i = 0; i < 16; i++)
            {
                if (((32768 >> i) & node.PrefixBitmap) == 0) continue;
                var extraBits = 0;
                uint tmp = prefixReconstruct;
                
                switch (i)
                {
                    case >= 7:
                        extraBits += 3;
                        tmp += (uint) ((i-7) << (level * 3 - 4));
                        break; 
                    case >= 3:
                        extraBits += 2;
                        tmp += (uint) ((i-3) << (level * 3 - 3));
                        break;
                    case >= 1:
                        extraBits += 1;
                        tmp += (uint) ((i-1) << (level * 3 - 2));
                        break;
                }

                yield return (tmp, (byte) (32-(level*3 -1)+extraBits), node.Prefix(i));
            }
            
            for (var i = 0; i < 8; i++)
            {
                if (((128 >> i) & node.ChildrenBitmap) == 0) continue;
                if (level == 0) break;
                
                if (level > 1) prefixReconstruct += (uint) (i << (level * 3 - 4));
                else prefixReconstruct += (uint) (i >> 1);

                foreach (var ipv4Route in EnumerateNode(node.Children(i), (byte) (level-1), prefixReconstruct)) yield return ipv4Route;
            }
        }
        
        public IEnumerator<(uint, byte, BgpRoute)> GetEnumerator()
        {
            return EnumerateNode(ToSafeIpv4Node(), 11, 0).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
        
        private unsafe SafeIpv4Node ToSafeIpv4Node() => new SafeIpv4Node(_oRootNode);

        public unsafe void AddRoute(uint ip, byte cidr, BgpRoute route)
        {
            var level = RootNode4;
            var targetLevel = 12 - (cidr/3 + (cidr%3+1)/2);
            
            var nodePtr = _oRootNode;
            int shift;
            byte ptr;
            
            while (targetLevel != level)
            {
                // Isolate correct part of IP into a PTR that is unqiue to the level
                shift = 32 - (3 * level - 1);
                ptr = (byte)((ip << shift) >> 29);

                // If no child array exists then allocate memory for it
                if ((*nodePtr).ChildrenBitmap == 0)
                {
                    (*nodePtr).Children = (Node*)Marshal.AllocHGlobal(8*ChildrenSize).ToPointer();
                    Unsafe.InitBlockUnaligned((*nodePtr).Children, 0, (uint) (8*ChildrenSize));
                }

                // If child does not exist then add it to keep moving down tree
                if (((128 >> ptr) & (*nodePtr).ChildrenBitmap) == 0) (*nodePtr).ChildrenBitmap += (byte) (128 >> ptr);

                nodePtr = (*nodePtr).Children + ptr;
                level--;
            }
            
            shift = 32 - (3 * level - 1);
            ptr = (byte)((ip << shift) >> 29);
            
            ptr = _treeLookup[ptr + ((cidr - shift) << 3)];

            // If no prefixes then allocate space for prefixes
            if (nodePtr->PrefixBitmap == 0) (*nodePtr).Prefixs = (BgpRoute*)Marshal.AllocHGlobal(15*PrefixSize).ToPointer();
            
            // Add route to prefix bitmap
            if ((nodePtr->PrefixBitmap & (32768 >> ptr)) == 0)
            {
                nodePtr->PrefixBitmap += (ushort)(32768 >> ptr);
            }
            
            // Put route into prefix array
            *(nodePtr->Prefixs + ptr) = route;
        }
        
        public unsafe BgpRoute LookupRoute(uint ip)
        {
            var level = 11;
            BgpRoute bestRoute = default;
            
            // Search each level of tree for prefixes belonging to IP
            var nodePtr = _oRootNode;
            while (true)
            {
                // Isolate correct part of IP into a PTR that is unqiue to the level
                var shift = 32 - (3 * level - 1);
                var ptr = (byte)((ip << shift) >> 29);
                var ptr2 = ptr+8;
                BgpRoute* prefixes = nodePtr->Prefixs;
                
                // Find best prefix among branch of branch belonging to IP
                if (((32768 >> ptr2-1) & nodePtr->PrefixBitmap) != 0) bestRoute = *(prefixes+ptr2-1);
                else if (((32768 >> (ptr2/2-1)) & nodePtr->PrefixBitmap) != 0) bestRoute = *(prefixes+ptr2/2-1);
                else if (((32768 >> (ptr2/4-1)) & nodePtr->PrefixBitmap) != 0) bestRoute = *(prefixes+ptr2/4-1);
                else if (((32768 >> (ptr2/8-1)) & nodePtr->PrefixBitmap) != 0) bestRoute = *(prefixes+ptr2/8-1);

                // If no level lower then current belonging to IP then end search
                if (((128 >> ptr) & nodePtr->ChildrenBitmap) == 0) break;
                
                // Drop down to next level of tree
                nodePtr = nodePtr->Children + ptr;
                level--;
            }

            return bestRoute;
        }
        
        public unsafe bool DeleteRoute(uint ip, byte cidr)
        {
            var level = RootNode4;
            var targetLevel = 12 - (cidr/3 + (cidr%3+1)/2);
            
            var nodePtr = _oRootNode;
            int shift;
            byte ptr;
            while (targetLevel != level)
            {
                // Isolate correct part of IP into a PTR that is unqiue to the level
                shift = 32 - (3 * level - 1);
                ptr = (byte)((ip << shift) >> 29);

                if (((128 >> ptr) & (*nodePtr).ChildrenBitmap) == 0) return false;
                
                // Navigate down tree
                nodePtr = (*nodePtr).Children + ptr;
                level--;
            }

            shift = 32 - (3 * level - 1);
            ptr = (byte)((ip << shift) >> 29);
            
            ptr = _treeLookup[ptr + (cidr - shift) << 3];
            
            if ((nodePtr->PrefixBitmap & (32768 >> ptr)) == 0) return false;
            
            nodePtr->PrefixBitmap -= (byte)(32768 >> ptr);
            return true;
        }
    }
    
    public sealed class Ipv4 : IEnumerable<(uint, byte, Ipv4.Ipv4Route)>, IDisposable
    {
        public unsafe Ipv4()
        {
            for (var i = 0; i < 2; i++) _treeLookup[0b01_000 + (i<<2)] = (byte) (i+1);
            for (var c = 0; c < 4; c++) _treeLookup[0b10_000 + (c<<1)] = (byte) (c+3);
            for (var z = 0; z < 8; z++) _treeLookup[0b11_000 + z] = (byte) (z + 7);

            _oRootNode =  (Node*) Marshal.AllocHGlobal(IntPtr.Size * 2 + 3).ToPointer();
            Unsafe.InitBlockUnaligned(_oRootNode, 0, (uint) ChildrenSize);
        }

        ~Ipv4()
        {
            Dispose();
        }
        
        public unsafe void Dispose()
        {
            GC.SuppressFinalize(this);
            DeleteChildrenRecursive(_oRootNode);
            Marshal.FreeHGlobal((IntPtr)_oRootNode);

            _oRootNode = (Node*) 0;
        }
                
        [StructLayout(LayoutKind.Sequential, Pack = 2)]
        public readonly struct Ipv4Route
        {
            public readonly uint NextHop;
            public readonly ushort Metric;

            public Ipv4Route(uint nexthop, ushort metric)
            {
                NextHop = nexthop;
                Metric = metric;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public unsafe struct Node
        {
            public Node* Children;
            public Ipv4Route* Prefixs;
            public byte ChildrenBitmap;
            public ushort PrefixBitmap;
        }
        
        private readonly byte[] _treeLookup = new byte[64];
        private unsafe Node* _oRootNode;
        private const byte RootNode4 =  11;
        private static readonly unsafe int ChildrenSize = sizeof(Node);
        private static readonly unsafe int PrefixSize = sizeof(Ipv4Route);
        
        private static unsafe void DeleteChildrenRecursive(Node* node)
        {
            Node* children = node->Children;
            
            if (node->PrefixBitmap != 0) Marshal.FreeHGlobal((IntPtr)node->Prefixs);
            if (node->ChildrenBitmap == 0) return;
            
            for (var i = 0; i < 8; i++)
            {
                if (((128 >> i) & node->ChildrenBitmap) != 0) DeleteChildrenRecursive(children + i);
            }
            
            Marshal.FreeHGlobal((IntPtr)node->Children);
        }
        
        private static unsafe bool CollectDeadBranches(Node* node)
        {
            Node* children = node->Children;

            var dead = true;
            for (var i = 0; i < 8; i++)
            {
                if (((128 >> i) & node->ChildrenBitmap) == 0) continue;
                if (!CollectDeadBranches(children + i)) dead = false;
            } 
            
            if (node->PrefixBitmap != 0) dead = false;

            if (dead && node->ChildrenBitmap != 0) Marshal.FreeHGlobal((IntPtr)node->Children);
            if (dead && node->PrefixBitmap != 0) Marshal.FreeHGlobal((IntPtr)node->Prefixs);
            
            return dead;
        }
        
        public unsafe bool CleanupDeadEntries() => CollectDeadBranches(_oRootNode);
        
        public unsafe void ClearAllEntries()
        {
            _oRootNode->ChildrenBitmap = 0;
            _oRootNode->PrefixBitmap = 0;
            DeleteChildrenRecursive(_oRootNode);
        }
        
        public class SafeIpv4Node
        {
            private readonly unsafe Node* _node;
            public unsafe SafeIpv4Node(Node* ptr) => _node = ptr;
            public unsafe SafeIpv4Node Children(int child) => new(_node->Children + child);
            public unsafe Ipv4Route Prefix(int prefix) => *(_node->Prefixs + prefix);
            public unsafe byte ChildrenBitmap => _node->ChildrenBitmap;
            public unsafe ushort PrefixBitmap => _node->PrefixBitmap;
        }
        
        private static IEnumerable<(uint, byte, Ipv4Route)> EnumerateNode(SafeIpv4Node node, byte level, uint prefixReconstruct)
        {

            for (var i = 0; i < 16; i++)
            {
                if (((32768 >> i) & node.PrefixBitmap) == 0) continue;
                var extraBits = 0;
                uint tmp = prefixReconstruct;
                
                switch (i)
                {
                    case >= 7:
                        extraBits += 3;
                        tmp += (uint) ((i-7) << (level * 3 - 4));
                        break; 
                    case >= 3:
                        extraBits += 2;
                        tmp += (uint) ((i-3) << (level * 3 - 3));
                        break;
                    case >= 1:
                        extraBits += 1;
                        tmp += (uint) ((i-1) << (level * 3 - 2));
                        break;
                }

                yield return (tmp, (byte) (32-(level*3 -1)+extraBits), node.Prefix(i));
            }
            
            for (var i = 0; i < 8; i++)
            {
                if (((128 >> i) & node.ChildrenBitmap) == 0) continue;
                if (level == 0) break;
                
                if (level > 1) prefixReconstruct += (uint) (i << (level * 3 - 4));
                else prefixReconstruct += (uint) (i >> 1);

                foreach (var ipv4Route in EnumerateNode(node.Children(i), (byte) (level-1), prefixReconstruct)) yield return ipv4Route;
            }
        }
        
        public IEnumerator<(uint, byte, Ipv4Route)> GetEnumerator()
        {
            return EnumerateNode(ToSafeIpv4Node(), 11, 0).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
        
        private unsafe SafeIpv4Node ToSafeIpv4Node() => new SafeIpv4Node(_oRootNode);

        public unsafe void AddRoute(uint ip, byte cidr, Ipv4Route route)
        {
            var level = RootNode4;
            var targetLevel = 12 - (cidr/3 + (cidr%3+1)/2);
            
            var nodePtr = _oRootNode;
            int shift;
            byte ptr;
            
            while (targetLevel != level)
            {
                // Isolate correct part of IP into a PTR that is unqiue to the level
                shift = 32 - (3 * level - 1);
                ptr = (byte)((ip << shift) >> 29);

                // If no child array exists then allocate memory for it
                if ((*nodePtr).ChildrenBitmap == 0)
                {
                    (*nodePtr).Children = (Node*)Marshal.AllocHGlobal(8*ChildrenSize).ToPointer();
                    Unsafe.InitBlockUnaligned((*nodePtr).Children, 0, (uint) (8*ChildrenSize));
                }

                // If child does not exist then add it to keep moving down tree
                if (((128 >> ptr) & (*nodePtr).ChildrenBitmap) == 0) (*nodePtr).ChildrenBitmap += (byte) (128 >> ptr);

                nodePtr = (*nodePtr).Children + ptr;
                level--;
            }
            
            shift = 32 - (3 * level - 1);
            ptr = (byte)((ip << shift) >> 29);
            
            ptr = _treeLookup[ptr + ((cidr - shift) << 3)];

            // If no prefixes then allocate space for prefixes
            if (nodePtr->PrefixBitmap == 0) (*nodePtr).Prefixs = (Ipv4Route*)Marshal.AllocHGlobal(15*PrefixSize).ToPointer();
            
            // Add route to prefix bitmap
            if ((nodePtr->PrefixBitmap & (32768 >> ptr)) == 0)
            {
                nodePtr->PrefixBitmap += (ushort)(32768 >> ptr);
            }
            
            // Put route into prefix array
            *(nodePtr->Prefixs + ptr) = route;
        }
        
        public unsafe Ipv4Route LookupRoute(uint ip)
        {
            var level = 11;
            Ipv4Route bestRoute = default;
            
            // Search each level of tree for prefixes belonging to IP
            var nodePtr = _oRootNode;
            while (true)
            {
                // Isolate correct part of IP into a PTR that is unqiue to the level
                var shift = 32 - (3 * level - 1);
                var ptr = (byte)((ip << shift) >> 29);
                var ptr2 = ptr+8;
                Ipv4Route* prefixes = nodePtr->Prefixs;
                
                // Find best prefix among branch of branch belonging to IP
                if (((32768 >> ptr2-1) & nodePtr->PrefixBitmap) != 0) bestRoute = *(prefixes+ptr2-1);
                else if (((32768 >> (ptr2/2-1)) & nodePtr->PrefixBitmap) != 0) bestRoute = *(prefixes+ptr2/2-1);
                else if (((32768 >> (ptr2/4-1)) & nodePtr->PrefixBitmap) != 0) bestRoute = *(prefixes+ptr2/4-1);
                else if (((32768 >> (ptr2/8-1)) & nodePtr->PrefixBitmap) != 0) bestRoute = *(prefixes+ptr2/8-1);

                // If no level lower then current belonging to IP then end search
                if (((128 >> ptr) & nodePtr->ChildrenBitmap) == 0) break;
                
                // Drop down to next level of tree
                nodePtr = nodePtr->Children + ptr;
                level--;
            }

            return bestRoute;
        }
        
        public unsafe bool DeleteRoute(uint ip, byte cidr)
        {
            var level = RootNode4;
            var targetLevel = 12 - (cidr/3 + (cidr%3+1)/2);
            
            var nodePtr = _oRootNode;
            int shift;
            byte ptr;
            while (targetLevel != level)
            {
                // Isolate correct part of IP into a PTR that is unqiue to the level
                shift = 32 - (3 * level - 1);
                ptr = (byte)((ip << shift) >> 29);

                if (((128 >> ptr) & (*nodePtr).ChildrenBitmap) == 0) return false;
                
                // Navigate down tree
                nodePtr = (*nodePtr).Children + ptr;
                level--;
            }

            shift = 32 - (3 * level - 1);
            ptr = (byte)((ip << shift) >> 29);
            
            ptr = _treeLookup[ptr + (cidr - shift) << 3];
            
            if ((nodePtr->PrefixBitmap & (32768 >> ptr)) == 0) return false;
            
            nodePtr->PrefixBitmap -= (byte)(32768 >> ptr);
            return true;
        }
    }
}
