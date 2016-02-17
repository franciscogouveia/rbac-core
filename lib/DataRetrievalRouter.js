'use strict';

const Joi = require('joi');
const Hoek = require('hoek');

const internals = {};
const schemas = {};
const defaults = {};

/**
 * Data retriever router object constructor.
 *
 * This object allows to register data retrieval handlers to obtain data form different sources.
 **/
exports = module.exports = internals.DataRetrievalRouter = function DataRetrievalRouter(options) {

    options = options || {};
    Joi.assert(options, schemas.DataRetrievalRouter_options);

    this.options = options;
    this.retrievers = {};
    this.parent = options.parent;
    this.context = options.context;
};
schemas.DataRetrievalRouter_options = Joi.object({
    override: Joi.boolean().optional(),
    parent: Joi.object().type(internals.DataRetrievalRouter).optional(),
    context: Joi.object().optional()
}).unknown(false);

/**
 * Create a child DataRetrievalRouter inheriting the current object, applied for a certain data context
 **/
internals.DataRetrievalRouter.prototype.createChild = function (context) {

    const options = Hoek.applyToDefaultsWithShallow(this.options, {
        parent: this,
        context: context
    }, ['parent', 'context']);

    return new internals.DataRetrievalRouter(options);
};

/**
 * Register a data retriever.
 *
 * * handles - A string or array of strings specifying what this component retrieves (source of data, e.g. 'credentials')
 * * retriever - A function which returns data, according to a key. Function signature is (source:string, key:string, context:object) => String
 * * options - (optional) A JSON with the following options:
 *   * override - When true, overrides existent handler if exists. When false, throws an error when a repeated handler is used. (default: false)
 **/
internals.DataRetrievalRouter.prototype.register = function (handles, retriever, options) {

    Joi.assert(handles, schemas.DataRetrievalRouter_register_handles);
    Joi.assert(retriever, schemas.DataRetrievalRouter_register_retriever);
    options = options || {};
    Joi.assert(options, schemas.DataRetrievalRouter_register_options);
    options = Hoek.applyToDefaults(defaults.DataRetrievalRouter_register_options, options);

    if (handles instanceof Array) {
        handles.forEach((source) => this._register(source, retriever, options));
    }
    else {
        this._register(handles, retriever, options);
    }

    return this;
};
schemas.DataRetrievalRouter_register_handles = Joi.alternatives().try(
    Joi.string().min(1),
    Joi.array().items(Joi.string().min(1))
);
schemas.DataRetrievalRouter_register_retriever = Joi.func().minArity(3).maxArity(4);
schemas.DataRetrievalRouter_register_options = Joi.object({
    override: Joi.boolean().optional()
}).unknown(false);

defaults.DataRetrievalRouter_register_options = {
    override: false
};

internals.DataRetrievalRouter.prototype._register = function (handles, retriever, options) {

    if (this.retrievers[handles] && !options.override) {
        throw new Error('There is a data retriever already registered for the source: ' + handles);
    }

    this.retrievers[handles] = retriever;
};

/**
 * Obtain data from a retriever.
 *
 * * key - Key value from the source (e.g. 'credentials:username')
 * * context - (optional) Context object. Contains the request object.
 * * callback - Function with the signature (err, result)
 **/
internals.DataRetrievalRouter.prototype.get = function (key, context, callback) {

    if (!callback) {
        if (context && context instanceof Function) {

            callback = context;
            context = null;
        } else {

            throw new Error('Callback not given');
        }
    }

    Joi.assert(key, schemas.DataRetrievalRouter_get_key);
    let source;
    let subkey;

    if (key.indexOf(':') === -1) {
        source = 'credentials'; // keep it backwards compatible
        subkey = key;
    }
    else {
        const split_key = key.split(':');
        source = split_key[0];
        subkey = split_key[1];
    }

    Joi.assert(subkey, schemas.DataRetrievalRouter_get_key);
    Joi.assert(source, schemas.DataRetrievalRouter_get_source);

    const fn = this.retrievers[source];

    if (!fn) {

        if (!this.parent) {

            return callback(null, null);
        }

        return this.parent.get(key, context || this.context, callback);
    }

    if (fn.length > 3) {

        // has callback
        try {
            return fn(source, subkey, context || this.context, callback);
        } catch(e) {
            return callback(e);
        }
    }

    let value;

    try {
        value = fn(source, subkey, context || this.context);
    } catch(e) {
        return callback(e);
    }

    callback(null, value);
};
schemas.DataRetrievalRouter_get_source = Joi.string().min(1);
schemas.DataRetrievalRouter_get_key = Joi.string().min(1);
