int mod_inverse(int a, int m)
{
    int x, y;
    int g = gcd(a, m, x, y);
    if (g != 1)
    {
        return -1;
    }
    return (x % m + m) % m;
}

int mod_exponentiation(int b, int e, int m)
{
    int c = 1;
    b = b % m;
    while (e > 0)
    {
        if (e % 2 == 1)
        {
            c = (c * b) % m;
        }
        e = e >> 1;
        b = (b * b) % m;
    }
    return c;
}