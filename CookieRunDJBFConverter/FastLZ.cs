unsafe static class FastLZ
{
    private const int MAX_COPY = 32;
    private const int MAX_LEN = 264; /* 256 + 8 */
    private const uint MAX_L1_DISTANCE = 8192;
    private const uint MAX_L2_DISTANCE = 8191;
    private const uint MAX_FARDISTANCE = 65535 + MAX_L2_DISTANCE - 1;
    private const int HASH_LOG = 14;
    private const int HASH_SIZE = 1 << HASH_LOG;
    private const uint HASH_MASK = HASH_SIZE - 1;

    /// <summary>
    /// Custom implementation that supports both levels
    /// <para>https://github.com/ariya/FastLZ</para>
    /// </summary>
    public static int Compress(byte* input, int length, byte* output)
    {
        int level = 1;
        uint max_distance = MAX_L1_DISTANCE;

        if (length >= 65536)
        {
            level = 2;
            max_distance = MAX_FARDISTANCE;
        }

        byte* ip = input;
        byte* ip_start = ip;
        byte* ip_bound = ip + length - 4; /* because readU32 */
        byte* ip_limit = ip + length - 12 - 1;
        byte* op = output;

        uint[] htab = new uint[HASH_SIZE];
        uint seq, hash;

        /* initializes hash table */
        for (hash = 0; hash < HASH_SIZE; ++hash)
            htab[hash] = 0;

        /* we start with literal copy */
        byte* anchor = ip;
        ip += 2;

        /* main loop */
        while (ip < ip_limit)
        {
            byte* ref_;
            uint distance, cmp;

            /* find potential match */
            do
            {
                seq = *(uint*)ip & 0xFFFFFF;
                hash = FastLZ_Hash(seq);
                ref_ = ip_start + htab[hash];
                htab[hash] = (uint)(ip - ip_start);
                distance = (uint)(ip - ref_);
                cmp = (distance < max_distance) ? *(uint*)ref_ & 0xFFFFFF : 0x1000000;

                if (ip >= ip_limit)
                    break;

                ++ip;
            } while (seq != cmp);

            if (ip >= ip_limit)
                break;

            --ip;

            /* far, needs at least 5-byte match */
            if (level == 2 && distance >= MAX_L2_DISTANCE)
            {
                if (ref_[3] != ip[3] || ref_[4] != ip[4])
                {
                    ++ip;
                    continue;
                }
            }

            if (ip > anchor)
                op = FastLZ_Literals((uint)(ip - anchor), anchor, op, 8);

            uint len = FastLZ_Cmp(ref_ + 3, ip + 3, ip_bound);

            if (level == 1)
                op = FastLZ_Match_1(len, distance, op);
            else
                op = FastLZ_Match_2(len, distance, op);

            /* update the hash at match boundary */
            ip += len;
            seq = *(uint*)ip;
            hash = FastLZ_Hash(seq & 0xffffff);
            htab[hash] = (uint)(ip++ - ip_start);
            seq >>= 8;
            hash = FastLZ_Hash(seq);
            htab[hash] = (uint)(ip++ - ip_start);

            anchor = ip;
        }

        uint copy = (uint)(input + length - anchor);
        op = FastLZ_Literals(copy, anchor, op, 1);

        /* marker for fastlz2 */
        if (level == 2)
            *output |= 1 << 5;

        return (int)(op - output);
    }

    /// <summary>
    /// Custom implementation that supports both levels
    /// <para>https://github.com/ariya/FastLZ</para>
    /// </summary>
    public static int Decompress(byte* input, int length, byte* output, int maxout)
    {
        // magic identifier for compression level
        int level = ((*input) >> 5) + 1;

        byte* ip = input;
        byte* ip_limit = ip + length;
        byte* ip_bound = ip_limit - 2;
        byte* op = output;
        byte* op_limit = op + maxout;
        uint ctrl = (uint)*ip++ & 31;

        while (true)
        {
            if (ctrl >= 32)
            {
                uint len = (ctrl >> 5) - 1;
                uint ofs = (ctrl & 31) << 8;
                byte* ref_ = op - ofs - 1;

                byte code;
                if (len == 7 - 1)
                {
                    do
                    {
                        if (ip > ip_bound)
                            break;

                        code = *ip++;
                        len += code;
                    }
                    while (level == 2 && code == 255);
                }

                code = *ip++;
                ref_ -= code;
                len += 3;

                // match from 16-bit distance
                if (level == 2 && code == 255)
                {
                    if (ofs == (31 << 8))
                    {
                        if (ip > ip_bound)
                            break;

                        ofs = (uint)*ip++ << 8;
                        ofs += *ip++;
                        ref_ = op - ofs - MAX_L2_DISTANCE - 1;
                    }
                }

                if (op + len > op_limit)
                    break;
                if (ref_ < output)
                    break;

                FastLZ_MemMove(op, ref_, len);
                op += len;
            }
            else
            {
                ctrl++;

                if (op + ctrl > op_limit)
                    break;
                if (ip + ctrl > ip_limit)
                    break;

                FastLZ_MemMove(op, ip, ctrl);
                ip += ctrl;
                op += ctrl;
            }

            if (level == 2 && ip >= ip_limit)
                break;
            if (level == 1 && ip > ip_bound)
                break;

            ctrl = *ip++;
        }

        return (int)(op - output);
    }

    private static void FastLZ_MemMove(byte* dest, byte* src, uint count)
    {
        do *dest++ = *src++;
        while (--count != 0);
    }

    private static uint FastLZ_Cmp(byte* p, byte* q, byte* r)
    {
        byte* start = p;

        while (q < r)
            if (*p++ != *q++)
                break;

        return (uint)(p - start);
    }

    private static byte* FastLZ_Match_1(uint len, uint distance, byte* op)
    {
        --distance;

        if (len < MAX_LEN - 2)
        {
            while (len > MAX_LEN - 2)
            {
                *op++ = (byte)((7 << 5) + (distance >> 8));
                *op++ = MAX_LEN - 2 - 7 - 2;
                *op++ = (byte)(distance & 255);
                len -= MAX_LEN - 2;
            }
        }

        if (len < 7)
        {
            *op++ = (byte)((len << 5) + (distance >> 8));
            *op++ = (byte)(distance & 255);
        }
        else
        {
            *op++ = (byte)((7 << 5) + (distance >> 8));
            *op++ = (byte)(len - 7);
            *op++ = (byte)(distance & 255);
        }

        return op;
    }

    private static byte* FastLZ_Match_2(uint len, uint distance, byte* op)
    {
        --distance;

        if (distance < MAX_L2_DISTANCE)
        {
            if (len < 7)
            {
                *op++ = (byte)((len << 5) + (distance >> 8));
                *op++ = (byte)(distance & 255);
            }
            else
            {
                *op++ = (byte)((7 << 5) + (distance >> 8));
                for (len -= 7; len >= 255; len -= 255) *op++ = 255;
                *op++ = (byte)len;
                *op++ = (byte)(distance & 255);
            }
        }
        else
        {
            /* far away, but not yet in the another galaxy... */
            if (len < 7)
            {
                distance -= MAX_L2_DISTANCE;
                *op++ = (byte)((len << 5) + 31);
                *op++ = 255;
                *op++ = (byte)(distance >> 8);
                *op++ = (byte)(distance & 255);
            }
            else
            {
                distance -= MAX_L2_DISTANCE;
                *op++ = (7 << 5) + 31;
                for (len -= 7; len >= 255; len -= 255) *op++ = 255;
                *op++ = (byte)len;
                *op++ = 255;
                *op++ = (byte)(distance >> 8);
                *op++ = (byte)(distance & 255);
            }
        }
        return op;
    }

    private static ushort FastLZ_Hash(uint v)
    {
        ulong h = (v * 2654435769UL) >> (32 - HASH_LOG);
        return (ushort)(h & HASH_MASK);
    }

    private static byte* FastLZ_Literals(uint runs, byte* src, byte* dest, byte size)
    {
        while (runs >= MAX_COPY)
        {
            *dest++ = MAX_COPY - 1;
            FastLZ_MemMove(dest, src, MAX_COPY);
            src += MAX_COPY;
            dest += MAX_COPY;
            runs -= MAX_COPY;
        }

        if (runs > 0)
        {
            *dest++ = (byte)(runs - 1);
            FastLZ_MemMove(dest, src, runs * size);
            dest += runs;
        }

        return dest;
    }
}
