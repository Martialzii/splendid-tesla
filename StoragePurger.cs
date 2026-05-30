using System;
using System.IO;

class StoragePurger
{
    static void Main()
    {
        // Get path to user's active Downloads folder
        string downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        string archivePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "SmartArchive");

        if (!Directory.Exists(downloadsPath))
        {
            Console.WriteLine("❌ Downloads directory not found.");
            return;
        }

        // Ensure archive directory exists
        if (!Directory.Exists(archivePath)) Directory.CreateDirectory(archivePath);

        Console.WriteLine("====================================================");
        // 
        Console.WriteLine("          SMART STORAGE PURGE ENGINE (V1)           ");
        Console.WriteLine($" 📍 Monitoring Target: {downloadsPath}");
        Console.WriteLine("====================================================\n");

        try
        {
            string[] files = Directory.GetFiles(downloadsPath);
            int deletedCount = 0;
            int archivedCount = 0;

            foreach (string file in files)
            {
                FileInfo fileInfo = new FileInfo(file);
                string extension = fileInfo.Extension.ToLower();
                
                // Define the age of the file in days
                double fileAgeDays = (DateTime.Now - fileInfo.LastWriteTime).TotalDays;

                // RULE 1: Instantly delete temporary setup/executable installers older than 3 days
                if ((extension == ".exe" || extension == ".msi") && fileAgeDays > 3)
                {
                    Console.WriteLine($"🔥 [PURGING EXECUTABLE]: {fileInfo.Name} ({Math.Round(fileAgeDays)} days old)");
                    fileInfo.Delete();
                    deletedCount++;
                }
                // RULE 2: Safely migrate bulky archives and documents older than 14 days to Desktop Archive
                else if ((extension == ".zip" || extension == ".pdf" || extension == ".docx") && fileAgeDays > 14)
                {
                    string destPath = Path.Combine(archivePath, fileInfo.Name);
                    
                    if (File.Exists(destPath)) File.Delete(destPath); // Prevent naming conflict crashes
                    
                    Console.WriteLine($"📦 [ARCHIVING DOCUMENT]: {fileInfo.Name} ➔ /SmartArchive");
                    File.Move(file, destPath);
                    archivedCount++;
                }
            }

            Console.WriteLine($"\n✨ [RUN SUCCESSFUL]: Cleaned up {deletedCount} temporary installers and archived {archivedCount} workspace assets.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ [CRITICAL FAULT]: Automation blocked: {ex.Message}");
        }
    }
}