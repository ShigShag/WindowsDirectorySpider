using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class Pathing
{
    [DllImport("mpr.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int WNetGetConnection(
        [MarshalAs(UnmanagedType.LPTStr)] string localName,
        [MarshalAs(UnmanagedType.LPTStr)] StringBuilder remoteName,
        ref int length);
    public static string GetUNCPath(string originalPath)
    {
        StringBuilder sb = new StringBuilder(512);
        int size = sb.Capacity;

        // look for the {LETTER}: combination ...
        if (originalPath.Length > 2 && originalPath[1] == ':')
        {
            // don't use char.IsLetter here - as that can be misleading
            // the only valid drive letters are a-z && A-Z.
            char c = originalPath[0];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
            {
                int error = WNetGetConnection(originalPath.Substring(0, 2),
                    sb, ref size);
                if (error == 0)
                {
                    DirectoryInfo dir = new DirectoryInfo(originalPath);

                    string path = Path.GetFullPath(originalPath)
                        .Substring(Path.GetPathRoot(originalPath).Length);
                    return Path.Combine(sb.ToString().TrimEnd(), path);
                }
            }
        }

        return originalPath;
    }
}