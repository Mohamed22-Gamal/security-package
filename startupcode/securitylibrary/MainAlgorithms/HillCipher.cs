using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;


namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher : ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            int b = 0, c = 0, w = 0, q = 0;
            while (true)
            {
                List<int> key = new List<int>();
                key.Add(b);
                key.Add(c);
                key.Add(w);
                key.Add(q);
                q++;
                if (q == 26)
                {
                    q = 0;
                    w++;
                    if (w == 26)
                    {
                        w = 0;
                        q = 0;
                        c++;
                        if (c == 26)
                        {
                            w = 0;
                            q = 0;
                            c = 0;
                            b++;
                            if (b == 26)
                            {
                                break;
                            }
                        }
                    }
                }
                List<int> t = new List<int>();
                t = Encrypt(plainText, key);
                if (t.SequenceEqual(cipherText))
                {
                    return key;
                }
            }
            throw new InvalidAnlysisException();

        }


        public string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            // throw new NotImplementedException();

            int counter = 0;
            int mxm = (int)Math.Sqrt(key.Count);
            int[,] keymatrixinverse = new int[mxm, mxm];
            int[,] keymatrix = new int[mxm, mxm];
            List<int> outputTempList1 = new List<int>();
            List<int> templist1;
            counter = 0;
            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    if ((key[counter] >= 0) && (key[counter] <= 26))
                        keymatrix[i, j] = key[counter++];
                    else if (key[counter] > 26)
                    {
                        //All elements are less than 26
                        int x = key[counter];
                        x %= 26;
                        keymatrix[i, j] = x;
                        counter++;
                    }
                    else
                    {
                        break;
                    }
                }
            } //convert keylist to keymatrtix
            int det = 0;
            if (mxm == 2)
            {
                det = keymatrix[0, 0] * keymatrix[1, 1] - keymatrix[0, 1] * keymatrix[1, 0];



                if (det > 26)
                {
                    det = det % 26;
                }



                while (det < 0)
                {
                    det += 26;
                }



                if (det == 1)
                {
                    det = 1;
                }
                else if (det == 3)
                {
                    det = 9;
                }
                else if (det == 5)
                {
                    det = 21;
                }
                else if (det == 7)
                {
                    det = 15;
                }
                else if (det == 9)
                {
                    det = 3;
                }
                else if (det == 11)
                {
                    det = 19;
                }
                else if (det == 15)
                {
                    det = 7;
                }
                else if (det == 17)
                {
                    det = 23;
                }
                else if (det == 19)
                {
                    det = 11;
                }
                else if (det == 21)
                {
                    det = 5;
                }
                else if (det == 23)
                {
                    det = 17;
                }
                else if (det == 25)
                {
                    det = 25;
                }
                else
                {
                    throw new Exception();
                }
                //Console.WriteLine(det);
                int n = cipherText.Count / 2;
                keymatrixinverse[0, 0] = ((int)Math.Pow(-1, 0) * keymatrix[1, 1]) % 26;
                keymatrixinverse[0, 1] = ((int)Math.Pow(-1, 1) * keymatrix[1, 0]) % 26;
                keymatrixinverse[1, 0] = ((int)Math.Pow(-1, 1) * keymatrix[0, 1]) % 26;
                keymatrixinverse[1, 1] = ((int)Math.Pow(-1, 2) * keymatrix[0, 0]) % 26;



                //Console.WriteLine(keymatrixinverse[0, 0]);



                for (int i = 0; i < mxm; i++)
                {
                    for (int j = 0; j < mxm; j++)
                    {
                        keymatrixinverse[i, j] *= det;
                        //Console.WriteLine(keymatrixinverse[i, j]);
                    }
                }




                List<int> tem = new List<int>();
                int x = cipherText.Count / 2;
                for (int i = 0; i < x; i++)
                {
                    templist1 = cipherText.GetRange(0, mxm);
                    for (int j = 0; j < mxm; j++)
                    {
                        int num = 0;
                        for (int row = 0; row < mxm; row++)
                        {
                            num += keymatrixinverse[row, j] * templist1[row];
                        }
                        outputTempList1.Add(num % 26);
                    }
                    cipherText.RemoveRange(0, mxm);
                }



                for (int i = 0; i < outputTempList1.Count; i++)
                {
                    if (outputTempList1[i] < 0)
                    {
                        outputTempList1[i] += 26;
                    }
                    // Console.WriteLine(outputTempList1[i]);
                }




                return outputTempList1;
            }



            else //3
            {



                for (int j = 0; j < mxm; j++)
                {
                    det += keymatrix[0, j] * (keymatrix[1, (j + 1) % mxm] * keymatrix[2, (j + 2) % mxm] -
                    keymatrix[1, (j + 2) % mxm] * keymatrix[2, (j + 1) % mxm]);
                }
                if (det > 26)
                {
                    det = det % 26;
                }



                while (det < 0)
                {
                    det += 26;
                }



                if (det > 26)
                {
                    det %= 26;
                }
                if (det == 1)
                {
                    det = 1;
                }
                else if (det == 3)
                {
                    det = 9;
                }
                else if (det == 5)
                {
                    det = 21;
                }
                else if (det == 7)
                {
                    det = 15;
                }
                else if (det == 9)
                {
                    det = 3;
                }
                else if (det == 11)
                {
                    det = 19;
                }
                else if (det == 15)
                {
                    det = 7;
                }
                else if (det == 17)
                {
                    det = 23;
                }
                else if (det == 19)
                {
                    det = 11;
                }
                else if (det == 21)
                {
                    det = 5;
                }
                else if (det == 23)
                {
                    det = 17;
                }
                else if (det == 25)
                {
                    det = 25;
                }
                else
                {
                    throw new Exception();
                }



                int r1, r2, r3;
                r1 = (int)(keymatrix[1, 1] * keymatrix[2, 2] - keymatrix[1, 2] * keymatrix[2, 1]);
                keymatrixinverse[0, 0] = (r1 * det) % 26;
                r2 = (int)((-1) * (keymatrix[1, 0] * keymatrix[2, 2] - keymatrix[1, 2] * keymatrix[2, 0]));
                keymatrixinverse[1, 0] = (r2 * det) % 26;
                r3 = (int)(keymatrix[1, 0] * keymatrix[2, 1] - keymatrix[1, 1] * keymatrix[2, 0]);
                keymatrixinverse[2, 0] = (r3 * det) % 26;
                r1 = (int)((-1) * (keymatrix[0, 1] * keymatrix[2, 2] - keymatrix[2, 1] * keymatrix[0, 2]));
                keymatrixinverse[0, 1] = (r1 * det) % 26;
                r2 = (int)(keymatrix[0, 0] * keymatrix[2, 2] - keymatrix[2, 0] * keymatrix[0, 2]);
                keymatrixinverse[1, 1] = (r2 * det) % 26;
                r3 = (int)((-1) * (keymatrix[0, 0] * keymatrix[2, 1] - keymatrix[2, 0] * keymatrix[0, 1]));
                keymatrixinverse[2, 1] = (r3 * det) % 26;
                r1 = (int)(keymatrix[0, 1] * keymatrix[1, 2] - keymatrix[0, 2] * keymatrix[1, 1]);
                keymatrixinverse[0, 2] = (r1 * det) % 26;
                r2 = (int)((-1) * (keymatrix[0, 0] * keymatrix[1, 2] - keymatrix[1, 0] * keymatrix[0, 2]));
                keymatrixinverse[1, 2] = (r2 * det) % 26;
                r3 = (int)(keymatrix[0, 0] * keymatrix[1, 1] - keymatrix[1, 0] * keymatrix[0, 1]);
                keymatrixinverse[2, 2] = (r3 * det) % 26;




                for (int a = 0; a < mxm; a++) // handeling -ve numbers
                {
                    for (int j = 0; j < mxm; j++)
                    {
                        if (keymatrixinverse[a, j] < 0)
                        {
                            keymatrixinverse[a, j] += 26;
                        }
                        else
                        {
                            keymatrixinverse[a, j] %= 26;
                        }



                    }
                }




                int res, res1, res2;
                List<int> norhan = new List<int>();
                double[,] v = new double[100, 100];
                res = (int)(keymatrixinverse[0, 0] * cipherText[0] + keymatrixinverse[0, 1] * cipherText[1]
                + keymatrixinverse[0, 2] * cipherText[2]) % 26;
                norhan.Add(res);




                res1 = (int)(keymatrixinverse[1, 0] * cipherText[0] + keymatrixinverse[1, 1] * cipherText[1]
                + keymatrixinverse[1, 2] * cipherText[2]) % 26;
                norhan.Add(res1);




                res2 = (int)(keymatrixinverse[2, 0] * cipherText[0] + keymatrixinverse[2, 1] * cipherText[1]
                + keymatrixinverse[2, 2] * cipherText[2]) % 26;
                norhan.Add(res2);




                res = (int)(keymatrixinverse[0, 0] * cipherText[3] + keymatrixinverse[0, 1] * cipherText[4]
                + keymatrixinverse[0, 2] * cipherText[5]) % 26;
                norhan.Add(res);




                res1 = (int)(keymatrixinverse[1, 0] * cipherText[3] + keymatrixinverse[1, 1] * cipherText[4]
                + keymatrixinverse[1, 2] * cipherText[5]) % 26;
                norhan.Add(res1);




                res2 = (int)(keymatrixinverse[2, 0] * cipherText[3] + keymatrixinverse[2, 1] * cipherText[4]
                + keymatrixinverse[2, 2] * cipherText[5]) % 26;
                norhan.Add(res2);




                res = (int)(keymatrixinverse[0, 0] * cipherText[6] + keymatrixinverse[0, 1] * cipherText[7]
                + keymatrixinverse[0, 2] * cipherText[8]) % 26;
                norhan.Add(res);




                res1 = (int)(keymatrixinverse[1, 0] * cipherText[6] + keymatrixinverse[1, 1] * cipherText[7]
                + keymatrixinverse[1, 2] * cipherText[8]) % 26;
                norhan.Add(res1);




                res2 = (int)(keymatrixinverse[2, 0] * cipherText[6] + keymatrixinverse[2, 1] * cipherText[7]
                + keymatrixinverse[2, 2] * cipherText[8]) % 26;
                norhan.Add(res2);




                if (cipherText.Count > norhan.Count)
                {
                    res = (int)(keymatrixinverse[0, 0] * cipherText[9] + keymatrixinverse[0, 1] * cipherText[10]
                    + keymatrixinverse[0, 2] * cipherText[11]) % 26;
                    norhan.Add(res);




                    res1 = (int)(keymatrixinverse[1, 0] * cipherText[9] + keymatrixinverse[1, 1] * cipherText[10]
                    + keymatrixinverse[1, 2] * cipherText[11]) % 26;
                    norhan.Add(res1);




                    res2 = (int)(keymatrixinverse[2, 0] * cipherText[9] + keymatrixinverse[2, 1] * cipherText[10]
                    + keymatrixinverse[2, 2] * cipherText[11]) % 26;
                    norhan.Add(res2);
                }




                for (int j = 0; j < norhan.Count; j++)
                {
                    Console.Write(norhan[j]);
                    Console.WriteLine('\n');
                }



                return norhan;
            }




            // throw new InvalidAnlysisException();
            return null;

        }


        public string Encrypt(string plainText, string key)
        {
            throw new NotImplementedException();
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> encrypted = new List<int>(plainText.Count);
            int rows = (int)Math.Sqrt(key.Count);//bngeeb 3add el rows
            int nol = plainText.Count;//tol el plaintext
            int numberofkeys = key.Count;//tol el key
            int i = 0;
            while (i < nol)//bmla el list b asfar
            {
                encrypted.Add(0);
                i++;
            }
            //3shan ye3rf el key matrix kam f kam el mafroud
            int place = 0;
            for (int j = 0; j < nol; j += rows)//bmshy 3laa el plaintext matrix bs bzed b 3add elrows kol mara 3shan a5od el col kolo
            {
                int rcounter = 0, sum = 0;
                int k = 0;
                do//3shan t7sb magmou3 kol col mn plain fe rows of matrix of key
                {
                    if (rcounter == rows)//lw wslnaa l a5r coloumn
                    {
                        sum %= 26;//b3ml ll mgmo3 mod 26
                        if (sum < 0)
                            sum += 26;
                        encrypted[place] = sum;//b7ot el magmou3 fe el list fe mkano
                        rcounter = 0;//brg3 asfr kol haga 3shan ageb magmou3 darb el keymatrix fe kol col
                        sum = 0;
                        place++;
                        if (k == numberofkeys)//lw 5alsna 5alas w 3adena 3la kolo ytl3 bara el loop
                            break;

                    }
                    int elementosum = plainText[j + rcounter];//bmshy behaa 3la plain text b el j w rowcounter (0+3)
                    int keytomultiple = key[k];//bgeeb el row ely hadrb feeh
                    sum += (elementosum * keytomultiple);//bdrb kol row fe coloumn w bzwdhom fe elmagmou3
                    rcounter++;
                    k++;

                } while (k <= numberofkeys);//l 7ad ma elkeey t5ls
            }
            return encrypted;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
        {
            int mxm = (int)Math.Sqrt(plainText.Count);
            double[,] cipherTextMatrix = new double[mxm, mxm];
            int counter = 0;
            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    if ((cipherText[counter] >= 0) && (cipherText[counter] <= 26))
                    {
                        cipherTextMatrix[i, j] = cipherText[counter++];
                        //  cc = cipherTextMatrix[j, i];
                    }

                    else if (cipherText[counter] > 26)
                    {
                        //All elements are less than 26

                        int x = cipherText[counter];
                        x %= 26;
                        cipherTextMatrix[j, i] = x;
                        counter++;
                    }
                    else
                    {
                        //All elements are nonnegative 

                        break;

                    }
                }
            }


            double[,] plainTextMatrix = new double[mxm, mxm];
            counter = 0;
            for (int i = 0; i < mxm; i++)
            {
                for (int j = 0; j < mxm; j++)
                {
                    if ((plainText[counter] >= 0) && (plainText[counter] <= 26))
                        plainTextMatrix[j, i] = plainText[counter++];
                    else if (plainText[counter] > 26)
                    {
                        //All elements are less than 26

                        int x = plainText[counter];
                        x %= 26;
                        plainTextMatrix[i, j] = x;
                        counter++;
                    }
                    else
                    {
                        //All elements are nonnegative
                        break;

                    }
                }
            }

            double det = 0;
            for (int j = 0; j < mxm; j++)
            {
                if (j == 1)
                {
                    det += (-1) * plainTextMatrix[0, j] * (plainTextMatrix[1, (j + 1) % mxm] * plainTextMatrix[2, (j + 2) % mxm] -
                         plainTextMatrix[1, (j + 2) % mxm] * plainTextMatrix[2, (j + 1) % mxm]);
                }
                else
                {
                    det += plainTextMatrix[0, j] * (plainTextMatrix[1, (j + 1) % mxm] * plainTextMatrix[2, (j + 2) % mxm] -
                          plainTextMatrix[1, (j + 2) % mxm] * plainTextMatrix[2, (j + 1) % mxm]);
                }
            }

            if (det > 26)
            {
                det = det % 26;
            }
            if (det > 0 && det < 26)
            {
                int r1 = 0, r2 = 0, r3 = 0;
                double[,] plainTextMatrix2 = new double[mxm, mxm]; // co factor matrix

                r1 = (int)(plainTextMatrix[1, 1] * plainTextMatrix[2, 2] - plainTextMatrix[1, 2] * plainTextMatrix[2, 1]);
                plainTextMatrix2[0, 0] = (r1 * det) % 26;


                r2 = (int)((-1) * (plainTextMatrix[1, 0] * plainTextMatrix[2, 2] - plainTextMatrix[1, 2] * plainTextMatrix[2, 0]));
                plainTextMatrix2[0, 1] = (r2 * det) % 26;


                r3 = (int)(plainTextMatrix[1, 0] * plainTextMatrix[2, 1] - plainTextMatrix[1, 1] * plainTextMatrix[2, 0]);
                plainTextMatrix2[0, 2] = (r3 * det) % 26;

                r1 = (int)((-1) * (plainTextMatrix[0, 1] * plainTextMatrix[2, 2] - plainTextMatrix[2, 1] * plainTextMatrix[0, 2]));
                plainTextMatrix2[1, 0] = (r1 * det) % 26;



                r2 = (int)(plainTextMatrix[0, 0] * plainTextMatrix[2, 2] - plainTextMatrix[2, 0] * plainTextMatrix[0, 2]);
                plainTextMatrix2[1, 1] = (r2 * det) % 26;



                r3 = (int)((-1) * (plainTextMatrix[0, 0] * plainTextMatrix[2, 1] - plainTextMatrix[2, 0] * plainTextMatrix[0, 1]));
                plainTextMatrix2[1, 2] = (r3 * det) % 26;


                r1 = (int)(plainTextMatrix[0, 1] * plainTextMatrix[1, 2] - plainTextMatrix[0, 2] * plainTextMatrix[1, 1]);
                plainTextMatrix2[2, 0] = (r1 * det) % 26;



                r2 = (int)((-1) * (plainTextMatrix[0, 0] * plainTextMatrix[1, 2] - plainTextMatrix[1, 0] * plainTextMatrix[0, 2]));
                plainTextMatrix2[2, 1] = (r2 * det) % 26;



                r3 = (int)(plainTextMatrix[0, 0] * plainTextMatrix[1, 1] - plainTextMatrix[1, 0] * plainTextMatrix[0, 1]);
                plainTextMatrix2[2, 2] = (r3 * det) % 26;

                for (int a = 0; a < mxm; a++) // handeling -ve numbers large numbers
                {
                    for (int j = 0; j < mxm; j++)
                    {
                        if (plainTextMatrix2[a, j] < 0)
                        {
                            plainTextMatrix2[a, j] += 26;
                        }
                        else
                        {
                            plainTextMatrix2[a, j] %= 26;
                        }

                    }
                }

                int res = 0, res1 = 0, res2 = 0;
                int[,] keymatrix = new int[mxm, mxm];// multiply cipher & p power -1 to get key 

                res = (int)(plainTextMatrix2[0, 0] * cipherTextMatrix[0, 0] + plainTextMatrix2[0, 1] * cipherTextMatrix[1, 0]
                             + plainTextMatrix2[0, 2] * cipherTextMatrix[2, 0]) % 26;
                keymatrix[0, 0] = res;

                res1 = (int)(plainTextMatrix2[0, 0] * cipherTextMatrix[0, 1] + plainTextMatrix2[0, 1] * cipherTextMatrix[1, 1]
                    + plainTextMatrix2[0, 2] * cipherTextMatrix[2, 1]) % 26;
                keymatrix[1, 0] = res1;

                res2 = (int)(plainTextMatrix2[0, 0] * cipherTextMatrix[0, 2] + plainTextMatrix2[0, 1] * cipherTextMatrix[1, 2]
                    + plainTextMatrix2[0, 2] * cipherTextMatrix[2, 2]) % 26;
                keymatrix[2, 0] = res2;

                res = (int)(plainTextMatrix2[1, 0] * cipherTextMatrix[0, 0] + plainTextMatrix2[1, 1] * cipherTextMatrix[1, 0]
                    + plainTextMatrix2[1, 2] * cipherTextMatrix[2, 0]) % 26;
                keymatrix[0, 1] = res;


                res1 = (int)(plainTextMatrix2[1, 0] * cipherTextMatrix[0, 1] + plainTextMatrix2[1, 1] * cipherTextMatrix[1, 1]
                   + plainTextMatrix2[1, 2] * cipherTextMatrix[2, 1]) % 26;
                keymatrix[1, 1] = res1;

                res2 = (int)(plainTextMatrix2[1, 0] * cipherTextMatrix[0, 2] + plainTextMatrix2[1, 1] * cipherTextMatrix[1, 2]
                    + plainTextMatrix2[1, 2] * cipherTextMatrix[2, 2]) % 26;
                keymatrix[2, 1] = res2;

                res = (int)(plainTextMatrix2[2, 0] * cipherTextMatrix[0, 0] + plainTextMatrix2[2, 1] * cipherTextMatrix[1, 0]
                  + plainTextMatrix2[2, 2] * cipherTextMatrix[2, 0]) % 26;
                keymatrix[0, 2] = res;

                res1 = (int)(plainTextMatrix2[2, 0] * cipherTextMatrix[0, 1] + plainTextMatrix2[2, 1] * cipherTextMatrix[1, 1]
                   + plainTextMatrix2[2, 2] * cipherTextMatrix[2, 1]) % 26;
                keymatrix[1, 2] = res1;


                res2 = (int)(plainTextMatrix2[2, 0] * cipherTextMatrix[0, 2] + plainTextMatrix2[2, 1] * cipherTextMatrix[1, 2]
                    + plainTextMatrix2[2, 2] * cipherTextMatrix[2, 2]) % 26;
                keymatrix[2, 2] = res2;

                List<int> key = new List<int>();// convert 2D array to list
                for (int h = 0; h < mxm; h++)
                {
                    for (int j = 0; j < mxm; j++)
                    {
                        key.Add(keymatrix[h, j]);
                    }
                }
                return key;
            }

            return null;
        }

    }
}