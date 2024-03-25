SECTIONS
{
    /*
    fancy kitties LLC
     */
    .text :
    {
        *( .text$Z )
        *( .text$X )
        *( .rdata* )
        *( .text$C )
    }
}