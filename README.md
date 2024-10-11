# Required 
Python version 3.10.x

# Running:
1. clone or download this project into a local directory
2. run `python VPCLogParser.py <log file location> <lookup table location> --output <output file loctation>` in the project directory. (NOTE: example files are located in ./res/example_logs.txt and ./res/example_lookup.csv)
3. output will be located in src directory or in location provided by the --output arg 

# Assumptions made:
1. log files are .txt files. Technically VPC log files can also be in .parquet format, but since we aren't allowed to use any non-default libraries, processing .parquet files is out of scope of the project.
2. log files have columns at the top and are seperated by commas. this code supports any log file format as long as it contains the columns: `dstport`, `protocol`, and `log-status`. It will fail due to an assertion error otherwise.

# Testing:
this code was tested on the sample flow logs and lookup table provided in the assessment email, which are located in the `res/` folder as examples. The output was compared to the example output in the email as well. An example output is located in the `res/` folder.  
