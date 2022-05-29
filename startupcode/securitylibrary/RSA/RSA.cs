using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {

            int fofo = p * q;
            double to = 0;
            double result = 1;
            int i = 0;
            int timetofinish = e / 2;
            while (i < timetofinish)
            {
                int vet = (M * M);
                to = (vet % fofo);
                result *= to;
                result %= fofo;
                i++;
            }
            if (e % 2 != 0)
            {
                to = (M % fofo);
                result *= to;
                result %= fofo;
            }
            result %= fofo;
            return (int)result;
        }
        private int worldmod(int b, int m)
        {
            int A1 = 1, A2 = 0, A3 = m, B1 = 0, B2 = 1, B3 = b;
            bool thisis = false;
            while (true)
            {
                if (B3 == 0)
                    thisis = true;
                if (B3 == 1)
                {
                    while (B2 < 0)
                        B2 += m;
                    return B2;
                }
                if (thisis == true)
                {
                    return 0;
                }
                int T1 = A1 - ((A3 / B3) * B1), T2 = A2 - ((A3 / B3) * B2), T3 = A3 - ((A3 / B3) * B3);
                A1 = B1;
                A2 = B2;
                A3 = B3;

                B1 = T1;
                B2 = T2;
                B3 = T3;
            }


            return 0;
        }
        public int Decrypt(int p, int q, int C, int e)
        {
            int va = p * q;
            int ah = p - 1;
            int sa = q - 1;
            int finito = ah * sa;
            double top = 0;
            double c2 = 0;
            int d = worldmod(e, finito);
            double result = 1;
            for (int i = 0; i < d / 2; i++)
            {
                c2 = C * C;
                top = (c2 % va);
                result *= top;
                result %= va;
            }
            if (d % 2 != 0)
            {
                top = (C % va);
                result *= top;
                result %= va;
            }
            result %= va;
            return (int)result;
        }


    }
}