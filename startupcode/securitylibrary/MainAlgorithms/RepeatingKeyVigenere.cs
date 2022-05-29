using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace SecurityLibrary
{

    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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


            for (int i = 2; i < ret.Length; i++)
            {
                if (ret[0] == ret[i] && ret[1] == ret[i + 1])
                {
                    ret = ret.Remove(i);

                }
            }
            Console.WriteLine(ret);
            return ret;

        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            if (key.Length < cipherText.Length)
            {
                int diff = cipherText.Length - key.Length;
                for (int i = 0; i < diff; i++)
                {
                    key += key[i];
                }

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
            Console.WriteLine(ret);
            return ret.ToLower();
        }



        public string Encrypt(string plainText, string key)
        {
            if (key.Length < plainText.Length)
            {
                int diff = plainText.Length - key.Length;
                for (int i = 0; i < diff; i++)
                {
                    key += key[i];//bmla alkey stream mn al key
                }
            }
            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)//algdwl
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