/* This software was developed by employees of the National Institute of
 * Standards and Technology (NIST), an agency of the Federal Government.
 * Pursuant to title 15 United States Code Section 105, works of NIST
 * employees are not subject to copyright protection in the United States
 * and are considered to be in the public domain.  As a result, a formal
 * license is not needed to use the software.
 * 
 * This software is provided by NIST as a service and is expressly
 * provided "AS IS".  NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
 * OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
 * AND DATA ACCURACY.  NIST does not warrant or make any representations
 * regarding the use of the software or the results thereof including, but
 * not limited to, the correctness, accuracy, reliability or usefulness of
 * the software.
 * 
 * Permission to use this software is contingent upon your acceptance
 * of the terms of this agreement.
 */
package gov.nist.appvet.tool.ioscheckipa;

import gov.nist.appvet.tool.ioscheckipa.util.FileUtil;
import gov.nist.appvet.tool.ioscheckipa.util.HttpUtil;
import gov.nist.appvet.tool.ioscheckipa.util.Logger;
import gov.nist.appvet.tool.ioscheckipa.util.Protocol;
import gov.nist.appvet.tool.ioscheckipa.util.ReportFormat;
import gov.nist.appvet.tool.ioscheckipa.util.ReportUtil;
import gov.nist.appvet.tool.ioscheckipa.util.ToolStatus;
import gov.nist.appvet.tool.ioscheckipa.Properties;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileItemFactory;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.io.FileUtils;

/**
 * This class implements a synchronous tool service.
 */
public class Service extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static final String reportName = "report";
	private static final Logger log = Properties.log;
	private static String appDirPath = null;
	private String appFilePath = null;
	private String htmlFileReportPath = null;
	private String pdfFileReportPath = null;
	private String fileName = null;
	private String appId = null;
	private StringBuffer reportBuffer = null;
	private String command = null;

	public Service() {
		super();
	}

	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		
		// Get received HTTP parameters and file upload
		FileItemFactory factory = new DiskFileItemFactory();
		ServletFileUpload upload = new ServletFileUpload(factory);
		List<FileItem> items = null;
		FileItem fileItem = null;

		try {
			items = upload.parseRequest(request);
		} catch (FileUploadException e) {
			e.printStackTrace();
		}

		// Get received items
		Iterator<FileItem> iter = items.iterator();
		FileItem item = null;
		while (iter.hasNext()) {
			item = (FileItem) iter.next();
			if (item.isFormField()) {
				// Get HTML form parameters
				String incomingParameter = item.getFieldName();
				String incomingValue = item.getString();
				if (incomingParameter.equals("appid")) {
					appId = incomingValue;
				}
			} else {
				// item is a file
				if (item != null) {
					fileItem = item;
					log.debug("Received file: " + fileItem.getName());
				}
			}
		}

		if (appId == null) {
			// All tool services require an AppVet app ID
			HttpUtil.sendHttp400(response, "No app ID specified");
			return;
		}
		if (fileItem != null) {
			// Get app file
			fileName = FileUtil.getFileName(fileItem.getName());
			if (!fileName.endsWith(".ipa")) {
				HttpUtil.sendHttp400(response,
						"Invalid app file: " + fileItem.getName());
				return;
			}
			
			// Create app directory
			appDirPath = Properties.TEMP_DIR + "/" + appId;
			File appDir = new File(appDirPath);
			if (!appDir.exists()) {
				appDir.mkdir();
			}
			
			// Create report paths
			htmlFileReportPath = Properties.TEMP_DIR + "/" + appId + "/"
					+ reportName + "." + Properties.reportFormat.toLowerCase();
			pdfFileReportPath = Properties.TEMP_DIR + "/" + appId + "/"
					+ reportName + ".pdf";
			
			appFilePath = Properties.TEMP_DIR + "/" + appId + "/" + fileName;
			
			if (!FileUtil.saveFileUpload(fileItem, appFilePath)) {
				HttpUtil.sendHttp500(response, "Could not save uploaded file");
				return;
			}
		} else {
			HttpUtil.sendHttp400(response, "No app was received.");
			return;
		}
		
		// If asynchronous, send acknowledgement back to AppVet
		if (Properties.protocol.equals(Protocol.ASYNCHRONOUS.name())) {
			HttpUtil.sendHttp202(response, "Received app " + appId
					+ " for processing.");
		}
		
		reportBuffer = new StringBuffer();

		// Start processing app
		log.debug("Executing checkIPA on app");
		command = getCommand();
		boolean succeeded = execute(command, reportBuffer);
		log.debug("Finished execution checkIPA on app - succeeded: " + succeeded);

		if (!succeeded) {
			log.error("Error detected: " + reportBuffer.toString());
			String errorReport = ReportUtil
					.getHtmlReport(
							response,
							fileName,
							ToolStatus.ERROR,
							reportBuffer.toString(),
							"Description: \tApp does not contain Android MasterKey or ExtraField vulnerabilities.\n\n",
							null,
							"Description: \tApp contains Android MasterKey and/or ExtraField vulnerabilities.\n\n",
							"Description: \tError or exception processing app.\n\n");
			// Send report to AppVet
			if (Properties.protocol.equals(Protocol.ASYNCHRONOUS.name())) {
				// Send report file in new HTTP Request to AppVet
				boolean fileSaved = FileUtil.saveReport(errorReport, htmlFileReportPath);
				if (fileSaved) {
					final StringBuffer reportBuffer = new StringBuffer();	
					boolean htmlToPdfSuccessful = 
							execute("wkhtmltopdf " + htmlFileReportPath + " " + pdfFileReportPath, reportBuffer);
					if (htmlToPdfSuccessful) {
						ReportUtil.sendInNewHttpRequest(appId, pdfFileReportPath,ToolStatus.ERROR);
					} else {
						log.error("Error generating PDF file " + pdfFileReportPath);
					}
				} else {
					log.error("Error writing HTML report " + htmlFileReportPath);
				}
			}
			return;
		}
		// Analyze report and generate tool status
		log.debug("Analyzing report for " + appFilePath);
		ToolStatus reportStatus = analyzeReport(reportBuffer.toString());
		log.debug("Result: " + reportStatus.name());
		String reportContent = null;
		
		// Get report
		if (Properties.reportFormat.equals(ReportFormat.HTML.name())) {
			reportContent = ReportUtil
					.getHtmlReport(
							response,
							fileName,
							reportStatus,
							reportBuffer.toString(),
							"Description: \tApp does not contain moderate or high severity issues.\n\n",
							"Description: \tApp contains one or more moderate-severity issues.\n\n",
							"Description: \tApp contains one or more high-severity issues.\n\n",
							"Description: \tError or exception processing app.\n\n");
		}
		
		// If report content is null or empty, stop processing
		if (reportContent == null || reportContent.isEmpty()) {
			log.error("Tool report is null or empty");
			return;
		}
		// Send report to AppVet
		if (Properties.protocol.equals(Protocol.ASYNCHRONOUS.name())) {
			// Send report file in new HTTP Request to AppVet
			boolean htmlFileSaved = FileUtil.saveReport(reportContent, htmlFileReportPath);
			if (htmlFileSaved) {
				final StringBuffer reportBuffer = new StringBuffer();	
				boolean htmlToPdfSuccessful = 
						execute("wkhtmltopdf " + htmlFileReportPath + " " + pdfFileReportPath, reportBuffer);
				if (htmlToPdfSuccessful) {
					ReportUtil.sendInNewHttpRequest(appId, pdfFileReportPath, reportStatus);
				} else {
					log.error("Error generating PDF file " + pdfFileReportPath);
				}
			} else {
				log.error("Error writing HTML report " + htmlFileReportPath);
			}
		}
		
		// Clean up
		if (!Properties.keepApps) {
			try {
				log.debug("Removing app " + appId + " files.");
				FileUtils.deleteDirectory(new File(appDirPath));
			} catch (IOException ioe) {
				log.error(ioe.getMessage());
			}
		}
		
		reportBuffer = null;
		// Clean up
		System.gc();
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

	public String getCommand() {
		// Get command from ToolProperties.xml file
		String cmd1 = Properties.IOS_CHECKIPA_FILES_HOME + "/bin/" + Properties.command;
		String cmd2 = null;
		if (cmd1.indexOf(Properties.APP_FILE_PATH) > -1) {
			// Add app file path
			cmd2 = cmd1.replace(Properties.APP_FILE_PATH, appFilePath);
		} else {
			cmd2 = cmd1;
		}
		log.debug("full command: " + cmd2);
		return cmd2;
	}

	private static boolean execute(String command, StringBuffer output) {
		List<String> commandArgs = Arrays.asList(command.split("\\s+"));
		ProcessBuilder pb = new ProcessBuilder(commandArgs);
		Process process = null;
		IOThreadHandler outputHandler = null;
		IOThreadHandler errorHandler = null;
		int exitValue = -1;
		try {
			if (command == null || command.isEmpty()) {
				log.error("Command is null or empty");
				return false;
			}
			log.debug("Executing " + command);
			process = pb.start();
			outputHandler = new IOThreadHandler(process.getInputStream());
			outputHandler.start();
			errorHandler = new IOThreadHandler(process.getErrorStream());

			errorHandler.start();

			if (process.waitFor(Properties.commandTimeout,
					TimeUnit.MILLISECONDS)) {

				// Process has waited and exited within the timeout
				exitValue = process.exitValue();
				if (exitValue == 0) {
					log.debug("Command terminated normally: \n"
							+ outputHandler.getOutput() + "\nErrors: "
							+ errorHandler.getOutput());
					StringBuffer resultOut = outputHandler.getOutput();
					output.append(resultOut);
					return true;
				} else {
					log.error("Command terminated abnormally: \n"
							+ outputHandler.getOutput() + "\nErrors: "
							+ errorHandler.getOutput());
					StringBuffer resultError = errorHandler.getOutput();
					output.append(resultError);
					return false;
				}
			} else {

				// Process exceed timeout or was interrupted
				log.error("Command timed-out or was interrupted: \n"
						+ outputHandler.getOutput() + "\nErrors: "
						+ errorHandler.getOutput());
				StringBuffer resultOutput = outputHandler.getOutput();
				StringBuffer resultError = errorHandler.getOutput();
				if (resultOutput != null) {
					output.append(resultOutput);
					return false;
				} else if (resultError != null) {
					output.append(resultError);
				} else {
					output.append(Properties.toolName + " timed-out");
				}
				return false;
			}
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		} catch (InterruptedException e) {
			e.printStackTrace();
			return false;
		} finally {
			if (outputHandler.isAlive()) {
				try {
					outputHandler.inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (errorHandler.isAlive()) {
				try {
					errorHandler.inputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			if (process.isAlive()) {
				process.destroy();
			}
		}
	}

	private static class IOThreadHandler extends Thread {
		private InputStream inputStream;
		private StringBuffer output = new StringBuffer();
		private static final String lineSeparator = System
				.getProperty("line.separator");;

		IOThreadHandler(InputStream inputStream) {
			this.inputStream = inputStream;
		}

		public void run() {
			Scanner br = null;
			br = new Scanner(new InputStreamReader(inputStream));
			String line = null;
			while (br.hasNextLine()) {
				line = br.nextLine();
				output.append(line + lineSeparator);
			}
			br.close();
		}

		public StringBuffer getOutput() {
			return output;
		}
	}

	// TODO
	public String getTxtReport() {
		return null;
	}

	// TODO
	public String getPdfReport() {
		return null;
	}

	// TODO
	public String getJsonReport() {
		return null;
	}
}
