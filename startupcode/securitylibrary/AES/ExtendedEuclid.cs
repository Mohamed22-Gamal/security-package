using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {


            //throw new NotImplementedException();

            int A1 = 1;
            int A2 = 0;
            int A3 = baseN;
            int B1 = 0;
            int B2 = 1;
            int B3 = number;
            double T1, T2, T3;
            double Q;
            bool looped = false;
            bool looped2 = false;
            bool looped3 = false;
            do
            {
                if (B3 == 0)
                    looped3 = true;
                else if (B3 == 1)
                {
                    if (B2 < 0)
                        B2 += 26;
                    looped2 = true;
                }
                if (looped3 == true)
                    return -1;
                if (looped2 == true)
                    return B2;
                T1 = A1 - (A3 / B3) * B1;
                T2 = A2 - (A3 / B3) * B2;
                T3 = A3 - (A3 / B3) * B3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = (int)T1;
                B2 = (int)T2;
                B3 = (int)T3;
            } while (true);

        }
    }
}