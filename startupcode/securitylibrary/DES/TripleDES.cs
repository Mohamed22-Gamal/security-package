using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string DesDecryption(string cipherText, string key)
        {
            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };

            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };

            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string bicipher = Convert.ToString(Convert.ToInt64(cipherText, 16), 2).PadLeft(64, '0');
            string bikey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string cpblck = "";
            string Rigm = "";
            int leno = bicipher.Length;
            for (int i = 0; i < leno / 2; i++)
            {
                cpblck = cpblck + bicipher[i];
                Rigm = Rigm + bicipher[i + leno / 2];
            }

            //premutate key by pc-1
            string tempak = "";
            List<string> C = new List<string>();
            List<string> D = new List<string>();

            for (int i = 0; i < 8; i++)
            {
                int j = 0;
                while (j < 7)
                {
                    tempak = tempak + bikey[PC_1[i, j] - 1];
                    j++;
                }

            }

            //C and D
            string c = tempak.Substring(0, 28);
            string d = tempak.Substring(28, 28);
            bool isthishappen = false;
            string temp = "";
            for (int ko = 0; ko <= 16; ko++)
            {
                C.Add(c);
                D.Add(d);
                temp = "";
                if (ko == 0)
                {
                    isthishappen = true;
                }
                else if (ko == 1)
                {
                    isthishappen = true;
                }
                else if (ko == 8)
                {
                    isthishappen = true;
                }
                else if (ko == 15)
                {
                    isthishappen = true;
                }
                else
                {
                    isthishappen = false;
                }

                if (isthishappen == true)
                {
                    temp = temp + c[0];
                    c = c.Remove(0, 1);
                    c = c + temp;
                    temp = "";
                    temp = temp + d[0];
                    d = d.Remove(0, 1);
                    d = d + temp;
                }
                else if (isthishappen == false)
                {
                    temp = temp + c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c = c + temp;
                    temp = "";
                    temp = temp + d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d = d + temp;
                }
            }

            List<string> keys = new List<string>();
            for (int i = 0; i < D.Count; i++)
            {
                keys.Add(C[i] + D[i]);
            }

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                tempak = "";
                temp = "";
                temp = keys[k];
                for (int i = 0; i < 8; i++)
                {
                    for (int e = 0; e < 6; e++)
                    {
                        tempak = tempak + temp[PC_2[i, e] - 1];
                    }
                }

                nkeys.Add(tempak);
            }

            //premutation by IP for plain text
            string ippp = "";
            for (int i = 0; i < 8; i++)
            {
                for (int e = 0; e < 8; e++)
                {
                    ippp = ippp + bicipher[IP[i, e] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ippp.Substring(0, 32);
            string r = ippp.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebiiit = "";
            string exorrrk = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int i = 0; i < 16; i++)
            {
                L.Add(r);
                exorrrk = "";
                ebiiit = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int e = 0; e < 8; e++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebiiit = ebiiit + r[EB[e, k] - 1];
                    }
                }
                int g = 0;
                do
                {
                    exorrrk = exorrrk + (nkeys[nkeys.Count - 1 - i][g] ^ ebiiit[g]).ToString();
                    g++;
                } while (g < ebiiit.Length);
                int z = 0;
                while (z < exorrrk.Length)
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exorrrk.Length)
                            t = t + exorrrk[y];
                    }

                    sbox.Add(t);
                    z += 6;
                }

                t = "";
                int sub = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    switch (s)
                    {
                        case 0:
                            sub = s1[row, col];
                            break;

                        case 1:
                            sub = s2[row, col];
                            break;

                        case 2:
                            sub = s3[row, col];
                            break;

                        case 3:
                            sub = s4[row, col];
                            break;

                        case 4:
                            sub = s5[row, col];
                            break;

                        case 5:
                            sub = s6[row, col];
                            break;

                        case 6:
                            sub = s7[row, col];
                            break;

                        case 7:
                            sub = s8[row, col];
                            break;
                    }

                    tsb = tsb + Convert.ToString(sub, 2).PadLeft(4, '0');
                }
                for (int jo = 0; jo < 8; jo++) { }

                x = "";
                h = "";

                for (int k = 0; k < 8; k++)
                {
                    for (int e = 0; e < 4; e++)
                    {
                        pp = pp + tsb[P[k, e] - 1];
                    }
                }

                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }

                r = lf;
                l = L[i + 1];
                R.Add(r);
            }

            string r16l16 = R[16] + L[16];
            string ciphertxt = "";
            for (int i = 0; i < 8; i++)
            {
                for (int e = 0; e < 8; e++)
                {
                    ciphertxt += r16l16[IP_1[i, e] - 1];
                }
            }
            for (int bb = 0; bb < 8; bb++) { }
            string plntxt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X").PadLeft(16, '0');
            return plntxt;
        }

        public string DesEncryption(string plainText, string key)
        {

            int[,] PC_1 = new int[8, 7] { { 57, 49, 41, 33, 25, 17, 9 }, { 1, 58, 50, 42, 34, 26, 18 }, { 10, 2, 59, 51, 43, 35, 27 }, { 19, 11, 3, 60, 52, 44, 36 }, { 63, 55, 47, 39, 31, 23, 15 }, { 7, 62, 54, 46, 38, 30, 22 }, { 14, 6, 61, 53, 45, 37, 29 }, { 21, 13, 5, 28, 20, 12, 4 } };

            int[,] PC_2 = new int[8, 6] { { 14, 17, 11, 24, 1, 5 }, { 3, 28, 15, 6, 21, 10 }, { 23, 19, 12, 4, 26, 8 }, { 16, 7, 27, 20, 13, 2 }, { 41, 52, 31, 37, 47, 55 }, { 30, 40, 51, 45, 33, 48 }, { 44, 49, 39, 56, 34, 53 }, { 46, 42, 50, 36, 29, 32 } };

            int[,] s1 = new int[4, 16] { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 }, { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 }, { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 }, { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 } };
            int[,] s2 = new int[4, 16] { { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 }, { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 }, { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 }, { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 } };
            int[,] s3 = new int[4, 16] { { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 }, { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 }, { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 }, { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 } };
            int[,] s4 = new int[4, 16] { { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 }, { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 }, { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 }, { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 } };
            int[,] s5 = new int[4, 16] { { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 }, { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 }, { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 }, { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 } };
            int[,] s6 = new int[4, 16] { { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 }, { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 }, { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 }, { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 } };
            int[,] s7 = new int[4, 16] { { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 }, { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 }, { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 }, { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 } };
            int[,] s8 = new int[4, 16] { { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 }, { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 }, { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 }, { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

            int[,] P = new int[8, 4] { { 16, 7, 20, 21 }, { 29, 12, 28, 17 }, { 1, 15, 23, 26 }, { 5, 18, 31, 10 }, { 2, 8, 24, 14 }, { 32, 27, 3, 9 }, { 19, 13, 30, 6 }, { 22, 11, 4, 25 } };
            int[,] EB = new int[8, 6] { { 32, 1, 2, 3, 4, 5 }, { 4, 5, 6, 7, 8, 9 }, { 8, 9, 10, 11, 12, 13 }, { 12, 13, 14, 15, 16, 17 }, { 16, 17, 18, 19, 20, 21 }, { 20, 21, 22, 23, 24, 25 }, { 24, 25, 26, 27, 28, 29 }, { 28, 29, 30, 31, 32, 1 } };


            int[,] IP = new int[8, 8] { { 58, 50, 42, 34, 26, 18, 10, 2 }, { 60, 52, 44, 36, 28, 20, 12, 4 }, { 62, 54, 46, 38, 30, 22, 14, 6 }, { 64, 56, 48, 40, 32, 24, 16, 8 }, { 57, 49, 41, 33, 25, 17, 9, 1 }, { 59, 51, 43, 35, 27, 19, 11, 3 }, { 61, 53, 45, 37, 29, 21, 13, 5 }, { 63, 55, 47, 39, 31, 23, 15, 7 } };

            int[,] IP_1 = new int[8, 8] { { 40, 8, 48, 16, 56, 24, 64, 32 }, { 39, 7, 47, 15, 55, 23, 63, 31 }, { 38, 6, 46, 14, 54, 22, 62, 30 }, { 37, 5, 45, 13, 53, 21, 61, 29 }, { 36, 4, 44, 12, 52, 20, 60, 28 }, { 35, 3, 43, 11, 51, 19, 59, 27 }, { 34, 2, 42, 10, 50, 18, 58, 26 }, { 33, 1, 41, 9, 49, 17, 57, 25 } };


            string biplain = Convert.ToString(Convert.ToInt64(plainText, 16), 2).PadLeft(64, '0');
            string bikey = Convert.ToString(Convert.ToInt64(key, 16), 2).PadLeft(64, '0');

            string Lmk = "";
            string Rgm = "";
            int leno = biplain.Length / 2;
            int i = 0;
            while (i < leno)
            {
                Lmk = Lmk + biplain[i];
                Rgm = Rgm + biplain[i + leno];
                i++;
            }

            //premutate key by pc-1
            string tmpkk = "";
            List<string> C = new List<string>();
            List<string> D = new List<string>();

            for (int m = 0; m < 8; m++)
            {
                for (int j = 0; j < 7; j++)
                {
                    tmpkk = tmpkk + bikey[PC_1[m, j] - 1];
                }
            }

            //C and D
            string c = tmpkk.Substring(0, 28);
            string d = tmpkk.Substring(28, 28);
            bool yesthishappen = false;
            string temp = "";
            for (int m = 0; m <= 16; m++)
            {
                C.Add(c);
                D.Add(d);
                temp = "";
                if (m == 0)
                {
                    yesthishappen = true;
                }
                else if (m == 1)
                {
                    yesthishappen = true;
                }
                else if (m == 8)
                {
                    yesthishappen = true;
                }
                else if (m == 15)
                {
                    yesthishappen = true;
                }
                else
                {
                    yesthishappen = false;
                }
                if (yesthishappen == true)
                {
                    temp = temp + c[0];
                    c = c.Remove(0, 1);
                    c = c + temp;
                    temp = "";
                    temp = temp + d[0];
                    d = d.Remove(0, 1);
                    d = d + temp;
                }
                else
                {
                    temp = temp + c.Substring(0, 2);
                    c = c.Remove(0, 2);
                    c = c + temp;
                    temp = "";
                    temp = temp + d.Substring(0, 2);
                    d = d.Remove(0, 2);
                    d = d + temp;
                }
            }

            List<string> keys = new List<string>();
            for (int m = 0; m < D.Count; m++)
            {
                keys.Add(C[m] + D[m]);
            }

            //k1 --> k16 by pc-2
            List<string> nkeys = new List<string>();
            for (int k = 1; k < keys.Count; k++)
            {
                tmpkk = "";
                temp = "";
                temp = keys[k];
                for (int m = 0; m < 8; m++)
                {
                    for (int j = 0; j < 6; j++)
                    {
                        tmpkk = tmpkk + temp[PC_2[m, j] - 1];
                    }
                }

                nkeys.Add(tmpkk);
            }


            //premutation by IP for plain text
            string ipaddr = "";
            for (int m = 0; m < 8; m++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ipaddr = ipaddr + biplain[IP[m, j] - 1];
                }
            }

            List<string> L = new List<string>();
            List<string> R = new List<string>();

            string l = ipaddr.Substring(0, 32);
            string r = ipaddr.Substring(32, 32);

            L.Add(l);
            R.Add(r);
            string x = "";
            string h = "";

            string ebity = "";
            string exorky = "";
            List<string> sbox = new List<string>();
            //string sb = "";
            string t = "";
            int row = 0;
            int col = 0;
            string tsb = "";
            string pp = "";
            string lf = "";

            for (int m = 0; m < 16; m++)
            {
                L.Add(r);
                exorky = "";
                ebity = "";
                lf = "";
                pp = "";
                sbox.Clear();
                tsb = "";
                col = 0;
                row = 0;
                t = "";
                for (int j = 0; j < 8; j++)
                {
                    for (int k = 0; k < 6; k++)
                    {
                        ebity = ebity + r[EB[j, k] - 1];
                    }
                }
                int g = 0;
                while (g < ebity.Length)
                {
                    exorky = exorky + (nkeys[m][g] ^ ebity[g]).ToString();
                    g++;
                }
                int z = 0;
                do
                {
                    t = "";
                    for (int y = z; y < 6 + z; y++)
                    {
                        if (6 + z <= exorky.Length)
                            t = t + exorky[y];
                    }

                    sbox.Add(t);
                    z = z + 6;
                } while (z < exorky.Length);
                for (int cc = 0; cc < 8; cc++) { }
                t = "";
                int sb = 0;
                for (int s = 0; s < sbox.Count; s++)
                {
                    t = sbox[s];
                    x = t[0].ToString() + t[5];
                    h = t[1].ToString() + t[2] + t[3] + t[4];

                    row = Convert.ToInt32(x, 2);
                    col = Convert.ToInt32(h, 2);
                    switch (s)
                    {
                        case 0:
                            sb = s1[row, col];
                            break;

                        case 1:
                            sb = s2[row, col];
                            break;

                        case 2:
                            sb = s3[row, col];
                            break;

                        case 3:
                            sb = s4[row, col];
                            break;

                        case 4:
                            sb = s5[row, col];
                            break;

                        case 5:
                            sb = s6[row, col];
                            break;

                        case 6:
                            sb = s7[row, col];
                            break;

                        case 7:
                            sb = s8[row, col];
                            break;
                    }

                    tsb = tsb + Convert.ToString(sb, 2).PadLeft(4, '0');
                }

                x = "";
                h = "";

                for (int k = 0; k < 8; k++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        pp = pp + tsb[P[k, j] - 1];
                    }
                }

                for (int k = 0; k < pp.Length; k++)
                {
                    lf = lf + (pp[k] ^ l[k]).ToString();
                }

                r = lf;
                l = L[m + 1];
                R.Add(r);
            }
            for (int y = 0; y < 8; y++) { }
            string r16l16 = R[16] + L[16];
            string ciphertxt = "";
            for (int m = 0; m < 8; m++)
            {
                for (int j = 0; j < 8; j++)
                {
                    ciphertxt += r16l16[IP_1[m, j] - 1];
                }
            }
            string ciphtxt = "0x" + Convert.ToInt64(ciphertxt, 2).ToString("X");

            return ciphtxt;


        }

        public string Decrypt(string cipherText, List<string> key)
        {
            string plain = "";

            plain = DesDecryption(cipherText, key[1]);
            plain = DesEncryption(plain, key[0]);
            plain = DesDecryption(plain, key[1]);

            return plain;
        }

        public string Encrypt(string plainText, List<string> key)
        {
            string encrypted = "";

            encrypted = DesEncryption(plainText, key[0]);
            encrypted = DesDecryption(encrypted, key[1]);
            encrypted = DesEncryption(encrypted, key[0]);

            return encrypted;
        }

        public List<string> Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}