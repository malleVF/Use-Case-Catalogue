---
tags: [T1221, atomic_test]
filename: "[[T1221 - Template Injection]]"
---
# T1221 - Template Injection

## Atomic Test #1 - WINWORD Remote Template Injection
Open a .docx file that loads a remote .dotm macro enabled template from https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1221/src/opencalc.dotm 
Executes the code specified within the .dotm template.
Requires download of WINWORD found in Microsoft Ofiice at Microsoft: https://www.microsoft.com/en-us/download/office.aspx.  
Default docs file opens Calculator.exe when test sucessfully executed, while AV turned off.

**Supported Platforms:** Windows


**auto_generated_guid:** 1489e08a-82c7-44ee-b769-51b72d03521d





#### Inputs:
| Name | Description | Type | Default Value |
|------|-------------|------|---------------|
| docx_file | Location of the test docx file on the local filesystem. | path | PathToAtomicsFolder&#92;T1221&#92;src&#92;Calculator.docx|


#### Attack Commands: Run with `command_prompt`! 


```cmd
start "#{docx_file}"
```






<br/>
