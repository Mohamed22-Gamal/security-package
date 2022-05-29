using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        char[,] arr = new char[26, 26];
        int findInMatrix(char letter, ref int row, ref int col)
        {
            for (int r = 0; r < 1; ++r)
                for (int c = 0; c < 26; ++c)
                    if (letter == arr[r, c])
                    {
                        row = r; col = c;
                    }
            return col;
        }

        public string Analyse(string plainText, string cipherText)
        {
            //  throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    arr[i, j] = (char)(((i + j) % 26) + 97);
                }
            }

            int row = 0, col = 0;
            string ret = "";
            int c = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                int v = findInMatrix(plainText[i], ref row, ref col);
                for (int j = 0; j < 26; j++)
                {
                    if (arr[j, v] == cipherText[c])
                    {
                        c++;
                        // cout << arr[j][v];
                        ret += arr[0, j];

                        break;
                    }
                }

            }

            for (int i = 0; i < ret.Length; i++)
            {
                if (ret[i] == plainText[0] && ret[i + 1] == plainText[1])
                {
                    ret = ret.Remove(i);
                }

            }

            Console.WriteLine(ret);
            return ret;
        }

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();

            int diff = 0;
            if (key.Length < cipherText.Length)
            {
                diff = cipherText.Length - key.Length;
            }
            int c = 0;
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    arr[i, j] = (char)(((i + j) % 26) + 97);

                }

            }
            int row = 0, col = 0, v;
            string ret = "";
            for (int i = 0; i < key.Length; i++)
            {
                v = findInMatrix(key[i], ref row, ref col);
                //cout << v << " ";

                for (int j = 0; j < 26; j++)
                {
                    if (arr[j, v] == cipherText[c])
                    {
                        c++;
                        // cout << arr[j][v];
                        ret += arr[0, j];

                        break;
                    }
                }
            }
            for (int i = 0; i < diff; i++)
            {
                v = findInMatrix(ret[i], ref row, ref col);
                //cout << v << " ";

                for (int j = 0; j < 26; j++)
                {
                    if (arr[j, v] == cipherText[c])
                    {
                        c++;
                        // cout << arr[j][v];
                        ret += arr[0, j];

                        break;
                    }
                }
            }

            Console.WriteLine(ret);
            return ret;
        }

        public string Encrypt(string plainText, string key)
        {
            if (key.Length < plainText.Length)
            {
                int diff = plainText.Length - key.Length;//size
                for (int i = 0; i < diff; i++)
                {
                    key += plainText[i]; //bmla al key stream bal7rof mn al plain text
                }

            }
            for (int i = 0; i < 26; i++) //b3ml al matrix bta3t al 7rof
            {
                for (int j = 0; j < 26; j++)
                {
                    arr[i, j] = (char)(((i + j) % 26) + 97); //asci

                }
            }
            int row = 0, col = 0;
            string ret = "";
            int c = 0;
            for (int i = 0; i < plainText.Length; i++)
            {
                int v = findInMatrix(plainText[i], ref row, ref col); //check found or not
                for (int j = 0; j < 26; j++)
                {
                    if (arr[j, 0] == key[c])
                    {
                        c++;
                        // cout << arr[j][v];
                        ret += arr[j, v];

                        break;
                    }
                }

            }
            //Console.WriteLine(ret);
            return ret;
        }
    }
}