using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            string result = "";
            int ascii_ct = 0;
            for (int i = 0; i < plainText.Length; i++)
            {

                if (char.IsUpper(plainText[i]))
                {
                    ascii_ct = ((key + (int)(plainText[i]) - 'A') % 26 + 'A');
                    result += (char)(ascii_ct);
                }
                else
                {
                    ascii_ct = ((key + (int)(plainText[i]) - 'a') % 26 + 'a');
                    result += (char)(ascii_ct);
                }

            }
            return result;
        }

        public string Decrypt(string cipherText, int key)
        {

            string result = "";
            int ascii_pt = 0;
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (char.IsUpper(cipherText[i]))
                {
                    ascii_pt = ((int)(cipherText[i]) - key - 'A' + 26) % 26 + 'A';
                    result += (char)(ascii_pt);
                }
                else
                {
                    ascii_pt = ((int)(cipherText[i]) - key - 'a' + 26) % 26 + 'a';
                    result += (char)(ascii_pt);
                }
            }

            return result;
        }

        public int Analyse(string plainText, string cipherText)
        {
            int result = 0;
            int ascii_pt = (int)(plainText[0]);
            int ascii_ct = (int)(char.ToLower(cipherText[0]));
            if ((ascii_ct - ascii_pt) < 0)
            {
                result = (ascii_ct - ascii_pt) + 26;
            }
            else
            {
                result = (ascii_ct - ascii_pt);
            }

            return result;
        }
    }
}