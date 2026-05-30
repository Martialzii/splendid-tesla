using System;
using System.IO;
using System.Diagnostics;

class AdminConsole
{
    static void Main()
    {
        // Explicitly map your active OneDrive directory paths
        string oneDrivePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OneDrive");
        string downloadsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        
        // Unified Data Pipeline paths pointing exactly to your OneDrive Desktop
        string baseWorkspace = Path.Combine(oneDrivePath, "Desktop", "DataPipeline");
        string inputDropzone = Path.Combine(baseWorkspace, "Input_Dropzone");
        string outputClean = Path.Combine(baseWorkspace, "Clean_Output");
        string archivePath = Path.Combine(baseWorkspace, "Archive");

        // Verify all directory structures are provisioned cleanly
        string[] paths = { inputDropzone, outputClean, archivePath, downloadsPath };
        foreach (var path in paths)
        {
            if (!Directory.Exists(path)) Directory.CreateDirectory(path);
        }

        Console.WriteLine("====================================================");
        Console.WriteLine("     UNIFIED SYSTEM ADMINISTRATOR CONSOLE (V1.1)    ");
        Console.WriteLine($" 📍 Base Workspace: {baseWorkspace}");
        Console.WriteLine("====================================================\n");

        // --- MODULE 1: EXECUTE BACKGROUND DATA INGESTION ---
        Console.WriteLine("🌐 [MODULE 1]: Triggering Python Scraper/Standardizer...");
        RunPythonEngine();

        // --- MODULE 2: DATA ROUTING & STANDARD ARCHIVING ---
        Console.WriteLine("\n⚡ [MODULE 2]: Routing newly standardized data files...");
        try
        {
            string[] cleanFiles = Directory.GetFiles(outputClean);
            int archiveCount = 0;
            foreach (string file in cleanFiles)
            {
                FileInfo fileInfo = new FileInfo(file);
                // Move clean production data logs older than 2 days to the master Archive folder
                if ((DateTime.Now - fileInfo.LastWriteTime).TotalDays > 2)
                {
                    string destFile = Path.Combine(archivePath, fileInfo.Name);
                    if (File.Exists(destFile)) File.Delete(destFile);
                    
                    File.Move(file, destFile);
                    archiveCount++;
                }
            }
            Console.WriteLine($"   -> Cleaned up and moved {archiveCount} records to storage archive.");
        }
        catch (Exception ex) { Console.WriteLine($"⚠️ Data routing paused: {ex.Message}"); }

        // --- MODULE 3: STORAGE MAINTENANCE & PURGING ---
        Console.WriteLine("\n🔥 [MODULE 3]: Executing system storage maintenance rules...");
        try
        {
            string[] downloadFiles = Directory.GetFiles(downloadsPath);
            int purges = 0;

            foreach (string file in downloadFiles)
            {
                FileInfo fileInfo = new FileInfo(file);
                string ext = fileInfo.Extension.ToLower();
                double age = (DateTime.Now - fileInfo.LastWriteTime).TotalDays;

                // Enforce retention rules on heavy temporary setup executables
                if ((ext == ".exe" || ext == ".msi") && age > 3)
                {
                    Console.WriteLine($"🗑️ [PURGED]: Removing expired setup file: {fileInfo.Name} ({Math.Round(age)} days old)");
                    fileInfo.Delete();
                    purges++;
                }
            }
            Console.WriteLine($"\n✨ [MAINTENANCE COMPLETE]: Cleaned out {purges} expired system assets from Downloads.");
        }
        catch (Exception ex) { Console.WriteLine($"❌ Storage purge failed: {ex.Message}"); }
    }

    static void RunPythonEngine()
    {
        ProcessStartInfo start = new ProcessStartInfo();
        start.FileName = "python"; 
        // Points exactly to your script sitting on your OneDrive desktop
        start.Arguments = @"C:\Users\Cyrus\OneDrive\Desktop\data_standardizer.py";
        start.UseShellExecute = false;
        start.RedirectStandardOutput = true;
        start.CreateNoWindow = true;

        try
        {
            using (Process process = Process.Start(start))
            {
                using (StreamReader reader = process.StandardOutput)
                {
                    string result = reader.ReadToEnd();
                    Console.WriteLine(result.Trim() == "" ? "   -> Subsystem ran silently." : result);
                }
            }
        }
        catch (Exception)
        {
            Console.WriteLine("   ⚠️ Python runner was unable to execute automatically.");
        }
    }
}