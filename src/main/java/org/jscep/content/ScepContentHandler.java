/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.content;

/**
 * This interface represents a mechanism for handling specific SCEP content.
 * 
 * @param <T>
 *            the content handled by the handler implementation
 * @author David Grant
 */
public interface ScepContentHandler<T> {
    /**
     * Read and interpret the content from the input stream.
     * 
     * @param response
     *            the content.
     * @param mimeType
     *            the type of the input stream.
     * @return the content in a usage form.
     * @throws InvalidContentTypeException
     *             if there is a problem decoding
     * @throws InvalidContentException
     *             if there is a problem with the message
     * @throws ContentException
     */
    T getContent(byte[] response, String mimeType) throws ContentException;
}
