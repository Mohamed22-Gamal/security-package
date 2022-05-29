using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {

            cipherText = cipherText.ToLower();
            int k = 0;
            bool c = false;
            for (int i = 1; i < cipherText.Length; i++)
            {
                for (int j = 1; j < plainText.Length; j++)
                {
                    if (cipherText[i] == plainText[j] && cipherText[i] != plainText[j + 1])
                    {
                        k = j;
                        c = true;
                        break;
                    }
                }
                if (c == true)
                {
                    break;
                }
            }

            return k;


        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = null;
            int count = 0;
            double colnum = 0.0;
            char[,] matrix = new char[key, 2000];
            cipherText = cipherText.ToLower();
            char[] ctca = cipherText.ToCharArray();
            colnum = (double)cipherText.Length / key;
            colnum = Math.Ceiling(colnum);

            for (int i = 0; i < key; i++)
            {
                for (int s = 0; s < (int)colnum; s++)
                {
                    if (count < cipherText.Length)
                    {
                        matrix[i, s] = ctca[count++];
                    }
                }
            }
            for (int s = 0; s < colnum; s++)
            {
                for (int x = 0; x < key; x++)
                {
                    try
                    {
                        plainText += matrix[x, s];
                    }
                    catch
                    {
                        break;
                    }
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            string ciphertext = null;
            int cont1 = 0;
            char[,] matrix = new char[key, 2000];
            char[] ptca = plainText.ToCharArray();
            for (int i = 0; i < ptca.Length; i += key)
            {
                for (int r = 0; r < key; r++)
                {
                    if ((i + r) < plainText.Length)
                    {
                        matrix[r, cont1] = ptca[i + r];// col is fixed untill its row finished
                    }

                }
                cont1++;
            }
            for (int x = 0; x < key; x++)
            {
                for (int s = 0; s < (int)((ptca.Length / key) + 1); s++)
                {
                    if (matrix[x, s] != '\0')
                    {
                        ciphertext += matrix[x, s];
                    }

                }
            }

            return ciphertext;
        }
    }
}