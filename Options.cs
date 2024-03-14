using System;
using System.Collections.Generic;
using System.Reflection;

namespace SharpConflux
{
	internal class Options
	{
		internal bool help = false;
		internal string url = null;
		internal string ua = "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko";
		internal bool cloud = false;
		internal bool onprem = false;
		internal string user = null;
		internal string pwd = null;
		internal bool basic = false;
		internal bool form = false;
		internal string apitoken = null;
		internal string pat = null;
		internal string cookies = null;
		internal string query = null;
		internal string cql = null;
		internal string limit = "10";
		internal string view = null;
		internal bool pretty = false;
		internal string download = null;
		internal bool b64 = false;
		internal string path = null;
		internal bool spaces = false;
		internal string upload = null;
		
		internal bool ParseArguments(string[] args)
		{
			FieldInfo[] fields = typeof(Options).GetFields(BindingFlags.Instance | BindingFlags.NonPublic);
			var parsedOptions = new HashSet<string>();
			foreach (string arg in args)
			{
				if (arg.StartsWith("/"))
				{
					var unknown = true;
					string[] argParts = arg.Split(new[] { ':' }, 2);
					string optionName = argParts[0].TrimStart('/').ToLower();
					foreach (FieldInfo field in fields)
					{
						if (optionName == field.Name.ToLower())
						{
							if (parsedOptions.Add(optionName))
							{
								if (argParts.Length == 1)
								{
									try
									{
										field.SetValue(this, true);
									}
									catch (ArgumentException)
									{
										Console.WriteLine($"[-] No value specified for argument '{optionName}'");
										return false;
									}
								}
								else
								{
									string optionValue = argParts[1];
									try
									{
										field.SetValue(this, optionValue);
									}
									catch (ArgumentException)
									{
										try
										{
											field.SetValue(this, int.Parse(optionValue));
										}
										catch (FormatException)
										{
											Console.WriteLine($"[-] Invalid value specified for argument '{optionName}'");
											return false;
										}
									}
								}
								unknown = false;
							}
							else
							{
								Console.WriteLine($"[-] '{optionName}' argument can only be specified once");
								return false;
							}
						}
					}

					if (unknown)
					{
						Console.WriteLine($"[-] Unknown argument '{optionName}'");
						return false;
					}
				}
			}
			return true;
		}
	}
}
