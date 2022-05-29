using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman
    {
        public double fun(double number, int power, int q)
        {
            double result = 1;
            int count = 0;

            while (count <= power - 1 && power > 0)
            {
                result = (result * number) % q;
                count++;
            }
            return result;
        }
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int[] key = new int[2];
            double ya, yb, y1, y2;
            ya = fun(alpha, xa, q);
            yb = fun(alpha, xb, q);
            y1 = fun(yb, xa, q);
            for (int i = 0; i < 2; i++)
            {
                key[i] = (int)y1;
            }
            y2 = fun(ya, xb, q);
            for (int i = 0; i < 2; i++)
            {
                key[i] = (int)y2;
            }
            return key.ToList();
        }
    }
}