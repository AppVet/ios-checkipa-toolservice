package gov.nist.appvet.tool.ioscheckipa.test;

import gov.nist.appvet.tool.ioscheckipa.Properties;
import gov.nist.appvet.tool.ioscheckipa.util.Logger;
import gov.nist.appvet.tool.ioscheckipa.util.ToolStatus;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class CheckIPATester {
	
	private static final Logger log = Properties.log;

	public CheckIPATester() {}
	
	private String readFile(String file) throws IOException {
	    BufferedReader reader = new BufferedReader(new FileReader (file));
	    String         line = null;
	    StringBuilder  stringBuilder = new StringBuilder();
	    String         ls = System.getProperty("line.separator");

	    try {
	        while((line = reader.readLine()) != null) {
	            stringBuilder.append(line);
	            stringBuilder.append(ls);
	        }

	        return stringBuilder.toString();
	    } finally {
	        reader.close();
	    }
	}
	
	public static ToolStatus analyzeReport(String report) {
		if (report == null || report.isEmpty()) {
			log.error("Report is null or empty.");
			return ToolStatus.ERROR;
		}
		// Scan file for result strings defined in configuration file. Here,
		// we always scan in this order: ERRORs, HIGHs, MODERATEs, and LOWs.
		if (Properties.errorResults != null
				&& !Properties.errorResults.isEmpty()) {
			for (String s : Properties.errorResults) {
				if (report.indexOf(s) > -1) {
					log.debug("Error message: " + s);
					return ToolStatus.ERROR;
				}
			}
		}
		if (Properties.highResults != null && !Properties.highResults.isEmpty()) {
			for (String s : Properties.highResults) {
				if (report.indexOf(s) > -1) {
					log.debug("High message: " + s);
					return ToolStatus.HIGH;
				}
			}
		}
		if (Properties.moderateResults != null
				&& !Properties.moderateResults.isEmpty()) {
			for (String s : Properties.moderateResults) {
				if (report.indexOf(s) > -1) {
					log.debug("Moderate message: " + s);
					return ToolStatus.MODERATE;
				}
			}
		}
		if (Properties.lowResults != null && !Properties.lowResults.isEmpty()) {
			for (String s : Properties.lowResults) {
				if (report.indexOf(s) > -1) {
					log.debug("Low message: " + s);
					return ToolStatus.LOW;
				}
			}
		}
		return Properties.defaultStatus;
	}
	
	public static void main(String[] args) {
		CheckIPATester tester = new CheckIPATester();
		try {
			String result = tester.readFile("/home/carwash/ios-checkipa-output.txt");
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
