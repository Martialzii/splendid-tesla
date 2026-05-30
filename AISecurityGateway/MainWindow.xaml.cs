using System;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Linq;

namespace AISecurityGateway
{
    public partial class MainWindow : Window
    {
        private string configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json");
        private FileSystemWatcher? fileWatcher;
        private bool isProcessing = false;
        private object processLock = new object();
        private bool runPending = false;

        // Metrics
        private int processedFilesCount = 0;
        private int redactedPiiCount = 0;
        private double storageReclaimedKb = 0;

        public MainWindow()
        {
            InitializeComponent();
            LoadSettings();
            SetupWatcher();
            RefreshDirectoryQueues();
            LogMessage("[SYSTEM INITIALIZED]: Zero-Trust Gateway ready.");
        }

        #region CONFIGURATION MANAGEMENT

        public class AppSettings
        {
            public string InputDropzone { get; set; } = @"C:\Users\Cyrus\OneDrive\Desktop\DataPipeline\Input_Dropzone";
            public string CleanOutput { get; set; } = @"C:\Users\Cyrus\OneDrive\Desktop\DataPipeline\Clean_Output";
            public string ArchivePath { get; set; } = @"C:\Users\Cyrus\OneDrive\Desktop\DataPipeline\Archive";
            public string PythonPath { get; set; } = "python";
            public string ScriptPath { get; set; } = @"C:\Users\Cyrus\Documents\antigravity\splendid-tesla\data_standardizer.py";
            public string OllamaModel { get; set; } = "llama3.2:3b";
        }

        private void LoadSettings()
        {
            AppSettings settings;
            try
            {
                if (File.Exists(configPath))
                {
                    string json = File.ReadAllText(configPath);
                    settings = JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
                }
                else
                {
                    settings = new AppSettings();
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[SETTINGS ERROR]: Failed to load settings: {ex.Message}. Using defaults.");
                settings = new AppSettings();
            }

            TxtInputDropzone.Text = settings.InputDropzone;
            TxtCleanOutput.Text = settings.CleanOutput;
            TxtArchive.Text = settings.ArchivePath;
            TxtPythonPath.Text = settings.PythonPath;
            TxtScriptPath.Text = settings.ScriptPath;
            
            // Set combo box selection
            foreach (ComboBoxItem item in CmbOllamaModel.Items)
            {
                if (item.Content.ToString() == settings.OllamaModel)
                {
                    item.IsSelected = true;
                    break;
                }
            }
            TxtStatusModel.Text = $"Local AI: {settings.OllamaModel}";
        }

        private void SaveSettings()
        {
            try
            {
                var settings = new AppSettings
                {
                    InputDropzone = TxtInputDropzone.Text.Trim(),
                    CleanOutput = TxtCleanOutput.Text.Trim(),
                    ArchivePath = TxtArchive.Text.Trim(),
                    PythonPath = TxtPythonPath.Text.Trim(),
                    ScriptPath = TxtScriptPath.Text.Trim(),
                    OllamaModel = (CmbOllamaModel.SelectedItem as ComboBoxItem)?.Content.ToString() ?? "llama3.2:3b"
                };

                string json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(configPath, json);
                
                TxtStatusModel.Text = $"Local AI: {settings.OllamaModel}";
                LogMessage("[SYSTEM CONFIG]: Settings saved successfully.");
                
                SetupWatcher();
                RefreshDirectoryQueues();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving settings: {ex.Message}", "Configuration Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        #endregion

        #region FILE WATCHER & PIPELINE RUNNER

        private void SetupWatcher()
        {
            try
            {
                if (fileWatcher != null)
                {
                    fileWatcher.EnableRaisingEvents = false;
                    fileWatcher.Dispose();
                    fileWatcher = null;
                }

                string dropzone = TxtInputDropzone.Text.Trim();
                if (Directory.Exists(dropzone) && ChkAutoWatcher.IsChecked == true)
                {
                    fileWatcher = new FileSystemWatcher(dropzone);
                    fileWatcher.Filter = "*.*";
                    fileWatcher.Created += OnDropzoneChanged;
                    fileWatcher.Changed += OnDropzoneChanged;
                    fileWatcher.Renamed += OnDropzoneChanged;
                    fileWatcher.EnableRaisingEvents = true;
                    StatusLedDot.Fill = (System.Windows.Media.Brush)FindResource("AccentMint");
                    LogMessage($"[WATCHER ACTIVE]: Monitoring {dropzone}");
                }
                else
                {
                    StatusLedDot.Fill = (System.Windows.Media.Brush)FindResource("AccentRed");
                    LogMessage("[WATCHER INACTIVE]: Directory monitoring disabled or path invalid.");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[WATCHER ERROR]: Failed to initialize watcher: {ex.Message}");
            }
        }

        private void OnDropzoneChanged(object sender, FileSystemEventArgs e)
        {
            // Trigger pipeline execution on a short delay to allow write operations to complete
            Task.Delay(500).ContinueWith(_ =>
            {
                Dispatcher.Invoke(() =>
                {
                    RefreshDirectoryQueues();
                    TriggerPipelineRun();
                });
            });
        }

        private void TriggerPipelineRun()
        {
            lock (processLock)
            {
                if (isProcessing)
                {
                    runPending = true;
                    return;
                }
                isProcessing = true;
            }

            // Run process on background thread
            Task.Run(async () =>
            {
                await RunPipelineAsync();
                
                lock (processLock)
                {
                    isProcessing = false;
                    if (runPending)
                    {
                        runPending = false;
                        Dispatcher.Invoke(TriggerPipelineRun);
                    }
                }
            });
        }

        private async Task RunPipelineAsync()
        {
            string python = "";
            string script = "";
            string dropzone = "";

            Dispatcher.Invoke(() =>
            {
                python = TxtPythonPath.Text.Trim();
                script = TxtScriptPath.Text.Trim();
                dropzone = TxtInputDropzone.Text.Trim();
                LogMessage("[PIPELINE START]: Initiating data standardization scan...");
            });

            if (!File.Exists(script))
            {
                Dispatcher.Invoke(() => LogMessage($"[PIPELINE ERROR]: Standardizer script not found at '{script}'"));
                return;
            }

            // Ensure directories exist
            try
            {
                if (!Directory.Exists(dropzone)) Directory.CreateDirectory(dropzone);
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => LogMessage($"[PIPELINE ERROR]: Directory error: {ex.Message}"));
                return;
            }

            ProcessStartInfo start = new ProcessStartInfo
            {
                FileName = python,
                Arguments = $"\"{script}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo = start;
                    
                    // Wire up asynchronous output reading
                    process.OutputDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                        {
                            Dispatcher.Invoke(() => ParseAndLogStdout(e.Data));
                        }
                    };

                    process.ErrorDataReceived += (sender, e) =>
                    {
                        if (e.Data != null)
                        {
                            Dispatcher.Invoke(() => LogMessage($"[PYTHON STDERR]: {e.Data}"));
                        }
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();

                    await process.WaitForExitAsync();
                    
                    Dispatcher.Invoke(() =>
                    {
                        LogMessage($"[PIPELINE COMPLETED]: Python finished with exit code {process.ExitCode}");
                        RefreshDirectoryQueues();
                    });
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() => LogMessage($"[PIPELINE EXCEPTION]: Failed to run python: {ex.Message}"));
            }
        }

        private void ParseAndLogStdout(string line)
        {
            // Output directly to live terminal
            LogMessage(line);

            // Parse metrics out of standardizer stdout
            if (line.Contains("[PII_REDACTED_STATS]"))
            {
                // Format: [PII_REDACTED_STATS]: file.txt - Phones: X, Emails: Y
                var match = Regex.Match(line, @"Phones:\s*(\d+),\s*Emails:\s*(\d+)");
                if (match.Success)
                {
                    int phones = int.Parse(match.Groups[1].Value);
                    int emails = int.Parse(match.Groups[2].Value);
                    redactedPiiCount += (phones + emails);
                    TxtRedactedCount.Text = redactedPiiCount.ToString();
                    LogMessage($"   🛡️ [METRIC SHIELD]: Redacted {phones} phone(s) and {emails} email(s) from log.");
                }
            }
            else if (line.Contains("[OLLAMA SUCCESS]"))
            {
                processedFilesCount++;
                TxtProcessedCount.Text = processedFilesCount.ToString();
            }
        }

        #endregion

        #region STORAGE MAINTENANCE OPERATIONS

        private void BtnScanDownloads_Click(object sender, RoutedEventArgs e)
        {
            string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            if (!Directory.Exists(downloads))
            {
                TxtStorageReport.Text = $"❌ Downloads folder not found at: {downloads}";
                return;
            }

            try
            {
                string[] files = Directory.GetFiles(downloads);
                int installerCount = 0;
                long installerBytes = 0;
                int docCount = 0;
                long docBytes = 0;

                foreach (var file in files)
                {
                    FileInfo fi = new FileInfo(file);
                    string ext = fi.Extension.ToLower();
                    double age = (DateTime.Now - fi.LastWriteTime).TotalDays;

                    if ((ext == ".exe" || ext == ".msi") && age > 3)
                    {
                        installerCount++;
                        installerBytes += fi.Length;
                    }
                    else if ((ext == ".zip" || ext == ".pdf" || ext == ".docx") && age > 14)
                    {
                        docCount++;
                        docBytes += fi.Length;
                    }
                }

                TxtStorageReport.Text = $"📍 Storage Inspection Results for Downloads:\n" +
                                       $"----------------------------------------------------\n" +
                                       $"Expired installers (.exe, .msi > 3 days old): {installerCount} files ({FormatSize(installerBytes)})\n" +
                                       $"Old documents (.zip, .pdf, .docx > 14 days old): {docCount} files ({FormatSize(docBytes)})\n" +
                                       $"Total scan capacity review completed.";
            }
            catch (Exception ex)
            {
                TxtStorageReport.Text = $"❌ Scan failed: {ex.Message}";
            }
        }

        private void BtnExecutePurge_Click(object sender, RoutedEventArgs e)
        {
            string downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
            string smartArchive = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "SmartArchive");
            
            if (!Directory.Exists(downloads))
            {
                TxtStorageReport.Text = $"❌ Downloads folder not found: {downloads}";
                return;
            }

            try
            {
                if (!Directory.Exists(smartArchive)) Directory.CreateDirectory(smartArchive);
                
                string[] files = Directory.GetFiles(downloads);
                int purges = 0;
                long purgedBytes = 0;
                int archives = 0;

                foreach (var file in files)
                {
                    FileInfo fi = new FileInfo(file);
                    string ext = fi.Extension.ToLower();
                    double age = (DateTime.Now - fi.LastWriteTime).TotalDays;

                    // Delete expired setup files
                    if (ChkPurgeExecutables.IsChecked == true && (ext == ".exe" || ext == ".msi") && age > 3)
                    {
                        purgedBytes += fi.Length;
                        fi.Delete();
                        purges++;
                    }
                    // Archive documents
                    else if (ChkArchiveDocuments.IsChecked == true && (ext == ".zip" || ext == ".pdf" || ext == ".docx") && age > 14)
                    {
                        string dest = Path.Combine(smartArchive, fi.Name);
                        if (File.Exists(dest)) File.Delete(dest);
                        File.Move(file, dest);
                        archives++;
                    }
                }

                double reclaimedKb = purgedBytes / 1024.0;
                storageReclaimedKb += reclaimedKb;
                TxtStorageReclaimed.Text = FormatSize(purgedBytes);

                TxtStorageReport.Text = $"🔥 STORAGE PURGE COMPLETED SUCCESSFULLY!\n" +
                                       $"----------------------------------------------------\n" +
                                       $"🗑️ Deleted installers: {purges} files ({FormatSize(purgedBytes)})\n" +
                                       $"📦 Documents archived: {archives} files (moved to Desktop/SmartArchive)\n" +
                                       $"✨ Reclaimed workspace memory.";
                LogMessage($"[STORAGE]: Purged {purges} installers and archived {archives} documents.");
            }
            catch (Exception ex)
            {
                TxtStorageReport.Text = $"❌ Purge interrupted: {ex.Message}";
            }
        }

        private void BtnRouteData_Click(object sender, RoutedEventArgs e)
        {
            string outputClean = TxtCleanOutput.Text.Trim();
            string archive = TxtArchive.Text.Trim();

            if (!Directory.Exists(outputClean))
            {
                TxtStorageReport.Text = $"❌ Clean Output directory does not exist: {outputClean}";
                return;
            }

            if (!double.TryParse(TxtRetentionDays.Text.Trim(), out double retentionDays))
            {
                MessageBox.Show("Please enter a valid numeric retention value.", "Validation Error", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                if (!Directory.Exists(archive)) Directory.CreateDirectory(archive);

                string[] files = Directory.GetFiles(outputClean);
                int moveCount = 0;

                foreach (var file in files)
                {
                    FileInfo fi = new FileInfo(file);
                    double age = (DateTime.Now - fi.LastWriteTime).TotalDays;

                    if (age > retentionDays)
                    {
                        string dest = Path.Combine(archive, fi.Name);
                        if (File.Exists(dest)) File.Delete(dest);
                        File.Move(file, dest);
                        moveCount++;
                    }
                }

                TxtStorageReport.Text = $"📦 DATA ROUTING LOG:\n" +
                                       $"----------------------------------------------------\n" +
                                       $"Routed {moveCount} standardized batch files older than {retentionDays} days to:\n" +
                                       $"📂 {archive}";
                LogMessage($"[ROUTING]: Moved {moveCount} files from Clean Output to Archive.");
                RefreshDirectoryQueues();
            }
            catch (Exception ex)
            {
                TxtStorageReport.Text = $"❌ Data routing failed: {ex.Message}";
            }
        }

        #endregion

        #region UTILITIES & NAVIGATION

        private void RefreshDirectoryQueues()
        {
            string dropzone = TxtInputDropzone.Text.Trim();
            string clean = TxtCleanOutput.Text.Trim();

            // Refresh Input Dropzone files
            try
            {
                if (Directory.Exists(dropzone))
                {
                    var files = Directory.GetFiles(dropzone).Select(Path.GetFileName).ToList();
                    LstDropzoneFiles.ItemsSource = files;
                    TxtInputQueueCount.Text = $"({files.Count} files)";
                }
                else
                {
                    LstDropzoneFiles.ItemsSource = null;
                    TxtInputQueueCount.Text = "(Dropzone Not Found)";
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[UI ERROR]: Refreshing input files failed: {ex.Message}");
            }

            // Refresh Clean Output files
            try
            {
                if (Directory.Exists(clean))
                {
                    var files = Directory.GetFiles(clean).Select(Path.GetFileName).ToList();
                    LstCleanFiles.ItemsSource = files;
                    TxtCleanOutputCount.Text = $"({files.Count} files)";
                }
                else
                {
                    LstCleanFiles.ItemsSource = null;
                    TxtCleanOutputCount.Text = "(Clean Folder Not Found)";
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[UI ERROR]: Refreshing clean files failed: {ex.Message}");
            }
        }

        private void LogMessage(string text)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            TxtConsoleLog.AppendText($"[{timestamp}] {text}\n");
            TxtConsoleLog.ScrollToEnd();
        }

        private string FormatSize(long bytes)
        {
            if (bytes >= 1073741824) return $"{bytes / 1073741824.0:F2} GB";
            if (bytes >= 1048576) return $"{bytes / 1048576.0:F2} MB";
            if (bytes >= 1024) return $"{bytes / 1024.0:F2} KB";
            return $"{bytes} B";
        }

        private void NavDashboard_Click(object sender, RoutedEventArgs e) => MainTabControl.SelectedIndex = 0;
        private void NavStorage_Click(object sender, RoutedEventArgs e) => MainTabControl.SelectedIndex = 1;
        private void NavSettings_Click(object sender, RoutedEventArgs e) => MainTabControl.SelectedIndex = 2;

        private void BtnClearLogs_Click(object sender, RoutedEventArgs e) => TxtConsoleLog.Clear();

        private void ChkAutoWatcher_Changed(object sender, RoutedEventArgs e) => SetupWatcher();

        private void BtnManualSweep_Click(object sender, RoutedEventArgs e)
        {
            LogMessage("[USER TRIGGER]: Manual pipeline execution triggered.");
            TriggerPipelineRun();
        }

        #endregion

        #region SETTINGS BROWSE CLICKS

        private void BtnBrowseDropzone_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select Input Dropzone Folder",
                InitialDirectory = TxtInputDropzone.Text
            };
            if (dialog.ShowDialog() == true) TxtInputDropzone.Text = dialog.FolderName;
        }

        private void BtnBrowseCleanOutput_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select Clean Output Folder",
                InitialDirectory = TxtCleanOutput.Text
            };
            if (dialog.ShowDialog() == true) TxtCleanOutput.Text = dialog.FolderName;
        }

        private void BtnBrowseArchive_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFolderDialog
            {
                Title = "Select Storage Archive Folder",
                InitialDirectory = TxtArchive.Text
            };
            if (dialog.ShowDialog() == true) TxtArchive.Text = dialog.FolderName;
        }

        private void BtnBrowsePython_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Select Python Executable",
                Filter = "Python Executable (python.exe)|python.exe|All files (*.*)|*.*"
            };
            if (dialog.ShowDialog() == true) TxtPythonPath.Text = dialog.FileName;
        }

        private void BtnBrowseScript_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Select Standardization Script",
                Filter = "Python Scripts (*.py)|*.py|All files (*.*)|*.*",
                InitialDirectory = Path.GetDirectoryName(TxtScriptPath.Text)
            };
            if (dialog.ShowDialog() == true) TxtScriptPath.Text = dialog.FileName;
        }

        private void BtnResetDefaults_Click(object sender, RoutedEventArgs e)
        {
            var defaults = new AppSettings();
            TxtInputDropzone.Text = defaults.InputDropzone;
            TxtCleanOutput.Text = defaults.CleanOutput;
            TxtArchive.Text = defaults.ArchivePath;
            TxtPythonPath.Text = defaults.PythonPath;
            TxtScriptPath.Text = defaults.ScriptPath;
            
            foreach (ComboBoxItem item in CmbOllamaModel.Items)
            {
                if (item.Content.ToString() == defaults.OllamaModel)
                {
                    item.IsSelected = true;
                    break;
                }
            }
            LogMessage("[SYSTEM CONFIG]: Fields reset to default values. Save to apply.");
        }

        private void BtnSaveSettings_Click(object sender, RoutedEventArgs e) => SaveSettings();

        #endregion
    }
}