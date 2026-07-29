/*
   A representative rule file. The word rule appears in this comment.
*/
rule Dropbear_Loader : trojan loader
{
    meta:
        author = "Analyst"
        description = "Detects the Dropbear loader stub"
        hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        hash2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        reference = "https://example.com/report"
    strings:
        $s1 = "evil.example.com"
        $s2 = "a}b"
        $h1 = { 6A 40 68 00 30 00 00 }
        $r1 = /ev[il]{2,3}\/x/
    condition:
        any of them
}

private global rule Shared_Helper
{
    meta:
        description = "A helper other rules include"
    condition:
        true
}
