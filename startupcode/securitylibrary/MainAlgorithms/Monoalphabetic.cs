using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            string alphabet = "abcdefghijklmnopqrstuvwxyz";
            char[] key = new char[26];
            bool[] check_key = new bool[26];
            int[] aray_of_ascii = new int[1000];
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (plainText[i] == alphabet[j])//lw el 7arf fy plaintext hwa hwa el 7arf fy alphabet
                    {
                        key[j] = cipherText[i];//7ot ll 7arf dah elkey b ek7arf ely fy cipher 
                        check_key[j] = true;//w 2ol en entaa maleto
                        aray_of_ascii[(int)cipherText[i]] = 1;//3lm ano atmlaa fe ascii
                    }
                }
            }

            for (int i = 0; i < alphabet.Length; i++)
            {
                if (check_key[i] == false)//lw fe haga lesa mgbnash elkey bta3haa mn alphabet
                {
                    for (int j = 0; j < alphabet.Length; j++)
                    {
                        if (aray_of_ascii[97 + j] != 1)//eh el 7arf ely lesa mt5dsh fe key w ynf3 na5do
                        {
                            key[i] = (char)(97 + j);//7oto fe elkey mn alphabet(mashy 3lehom b tarteeb) 
                            check_key[i] = true;//3lm ano b true fe el alpha en galo key
                            aray_of_ascii[97 + j] = 1;//3lm ano true k ascii
                            break;
                        }
                    }
                }
            }
            string ret = "";
            for (int r = 0; r < key.Length; r++)
            {
                ret += (char)key[r];// 5azno fe string w ab3to ano el key
            }
            // Console.WriteLine(key);
            return ret;
        }
        public string Decrypt(string cipherText, string key)
        {
            string ciphe = cipherText.ToLower();
            //throw new NotImplementedException();
            char[] plaint = new char[cipherText.Length];
            char[] alphabet = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (ciphe[i] == key[j])
                    {
                        plaint[i] = alphabet[j];
                    }
                }
            }
            return new string(plaint);
        }

        public string Encrypt(string plainText, string key)
        {
            char[] citext = new char[plainText.Length];
            char[] alphabet = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
            for (int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < key.Length; j++)
                {
                    if (plainText[i] == alphabet[j])//bmshy 3laa plain text w ashof el7arf dah any 7arf fy el alpha w ashel w a7ot el7arf
                                                    //ely b nafs elindex bta3o fy elkey
                    {
                        citext[i] = key[j];
                    }
                }
            }
            return new string(citext);
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        struct maker
        {
            public int counter;
            public char myalpha;
            public char secalpha;
        }
        maker[] yarab = new maker[26];
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            string freq = "etaoinsrhldcumfpgwybvkxjqz";
            char[] plaine = new char[cipher.Length];
            string ciphe = cipher.ToLower();
            for (int i = 0; i < 26; i++)//bmshy mn awl el a fy ascii w a7ot kol el 7rof fy el array
            {
                int ind = 97 + i;
                yarab[i].myalpha = (char)ind;
            }
            for (int j = 0; j < cipher.Length; j++)//bmshy 3la cipher
            {
                for (int l = 0; l < 26; l++)//bmshy 3la el7roof
                {
                    if (yarab[l].myalpha == ciphe[j])///bzwd el counter ll 7arf kol ma ytkrr fy text
                    {
                        yarab[l].counter++;
                    }
                }
            }
            for (int z = 0; z < 26; z++)
            {
                for (int k = z + 1; k < 26; k++)
                {
                    if (yarab[z].counter < yarab[k].counter)//b3dy 3la el7arf w ely b3do w b sort b el counter
                    {
                        char temp = yarab[z].myalpha;
                        int temp2 = yarab[z].counter;
                        yarab[z].myalpha = yarab[k].myalpha;
                        yarab[z].counter = yarab[k].counter;
                        yarab[k].myalpha = temp;
                        yarab[k].counter = temp2;
                    }
                }
            }
            for (int m = 0; m < 26; m++)//b7ot 7rof freq
            {
                yarab[m].secalpha = freq[m];
            }
            for (int n = 0; n < cipher.Length; n++)
            {
                for (int v = 0; v < 26; v++)
                {
                    if (ciphe[n] == yarab[v].myalpha)//bshof kol 7arf fy cipher zay el7arf fy alpha
                    {
                        plaine[n] = yarab[v].secalpha;//a7ot fy plaine el7arf ely zayo mn freq
                    }
                }
            }
            return new string(plaine);
        }
    }
}