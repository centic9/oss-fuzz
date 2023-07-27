// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.util.Iterator;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.csv.DuplicateHeaderMode;
import org.apache.commons.csv.QuoteMode;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

/**
 * This class provides a simple target for fuzzing Apache Commons CSV with Jazzer.
 *
 * It uses the fuzzed input data to try to parse CSV files.
 *
 * It catches all exceptions that are currently expected.
 */
public class CSVFormatFuzzer {
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		CSVFormat.Builder builder = CSVFormat.Builder.create();

		final CSVFormat format;
		try {
			builder.setDuplicateHeaderMode(
					DuplicateHeaderMode.values()[data.consumeInt(0, DuplicateHeaderMode.values().length-1)]);
			builder.setAllowMissingColumnNames(data.consumeBoolean());
			builder.setAutoFlush(data.consumeBoolean());
			builder.setCommentMarker(data.consumeChar());
			builder.setDelimiter(data.consumeChar());
			if (data.consumeBoolean()) {
				builder.setDelimiter(data.consumeString(10));
			}
			if (data.consumeBoolean()) {
				builder.setEscape(data.consumeChar());
			} else {
				builder.setEscape(null);
			}
			if (data.consumeBoolean()) {
				builder.setHeader(data.consumeString(10));
				builder.setHeaderComments(data.consumeString(10));
			}
			builder.setIgnoreEmptyLines(data.consumeBoolean());
			builder.setIgnoreHeaderCase(data.consumeBoolean());
			builder.setIgnoreSurroundingSpaces(data.consumeBoolean());
			if (data.consumeBoolean()) {
				builder.setNullString(data.consumeString(10));
			}
			if (data.consumeBoolean()) {
				builder.setQuote(data.consumeChar());
				int index = data.consumeInt(0, QuoteMode.values().length) - 1;

				// jazzer sometimes provides -1 here !?
				if (index >= 0) {
					builder.setQuoteMode(QuoteMode.values()[index]);
				}
			} else {
				builder.setQuote(null);
			}
			builder.setRecordSeparator(data.consumeChar());
			builder.setSkipHeaderRecord(data.consumeBoolean());
			builder.setTrailingDelimiter(data.consumeBoolean());
			builder.setTrim(data.consumeBoolean());

			format = builder.build();
		} catch (IllegalArgumentException e) {
			// input does not produce a valid format, so we cannot continue
			return;
		}

		// get fuzz-data for printing afterwards before consuming the remaining bytes
		boolean newRecord = data.consumeBoolean();
		String string = data.consumeString(100);

		byte[] inputData = data.consumeRemainingAsBytes();
		checkCSV(inputData, format);

		try {
			format.print(new StringReader(string), NULL_APPENDABLE, newRecord);
		} catch (IOException e) {
			// expected here
		}

		format.format();
		format.format("a");
	}

	@SuppressWarnings({ "ResultOfMethodCallIgnored", "EqualsBetweenInconvertibleTypes", "EqualsWithItself" })
	public static void checkCSV(byte[] inputData, CSVFormat format) {
		// trigger some methods of the format which should never throw an exception
		format.hashCode();
		format.toString();
		format.equals(null);
		format.equals("bla");
		format.equals(format);
		format.equals(CSVFormat.DEFAULT);

		try (InputStream stream = new ByteArrayInputStream(inputData);
				Reader in = new BufferedReader(new InputStreamReader(stream), 100*1024)) {
			try (CSVParser records = format.parse(in)) {

				Iterator<CSVRecord> it = records.iterator();
				//noinspection WhileLoopReplaceableByForEach
				while (it.hasNext()) {
					CSVRecord record = it.next();
					record.getComment();
					record.toString();
					record.toList();
					record.values();
					record.getRecordNumber();
					record.getParser();
					record.getCharacterPosition();
					record.size();
					try {
						record.get("head");
					} catch (IllegalStateException | IllegalArgumentException e) {
						// expected here
					}
					try {
						record.get(0);
					} catch (ArrayIndexOutOfBoundsException e) {
						// expected here
					}

					records.getFirstEndOfLine();
					records.getCurrentLineNumber();
					records.getRecordNumber();
				}

				records.stream();
				records.hasHeaderComment();
				records.hasTrailerComment();
				records.getHeaderComment();
				records.getTrailerComment();
				records.getRecords();
				records.getHeaderNames();
				records.getHeaderMap();

				try (CSVPrinter printer = format.print(NULL_APPENDABLE)) {
					printer.printRecords(records);
				}
			}
		} catch (IOException | UncheckedIOException | IllegalStateException | NegativeArraySizeException | IllegalArgumentException e) {
			// expected here
		}
	}

	private static final Appendable NULL_APPENDABLE = new PrintStream(OutputStream.nullOutputStream());
}
